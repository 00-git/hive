/**
 * hive federation listener — the ACCEPTING half of a hive node.
 *
 * There is no center here. Every node runs this listener so any peer can reach
 * it, and it holds no authority at all: identity is self-sovereign (a peer's
 * key pair IS its identity) and the peer directory is not kept here — peers
 * exchange their own tables. Losing any single node therefore strands nothing.
 *
 * Two kinds of connection arrive:
 *   role:"user"  the LOCAL operator surface (fedctl, the settings card), gated
 *                by a loopback-only token. Never federated, and never a
 *                credential any other machine can present.
 *   role:"host"  a peer, which must complete the mutual Ed25519 handshake and
 *                hold an operator-confirmed trust row before it may do anything.
 */
import { WebSocketServer, WebSocket } from 'ws'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
// Everything comes through hive-fed-peer, which re-exports the whole protocol
// surface. Importing fed-protocol directly as well would resolve to a SECOND
// copy of its branded types, and ids from the two copies are not assignable.
import {
  FedErrorCode,
  FedEventCatalog,
  FedMethod,
  TrustTable,
  acceptorOnAuthenticate,
  acceptorOnConnect,
  acceptorOnTrustApproved,
  decodeFrame,
  fedError,
  keepConnection,
  loadOrCreateIdentity,
  localTokenMatches,
  newAcceptorState,
  resolveListenTarget,
  toFedError,
  trustPersistenceFor,
  PeerTable,
  type AcceptorState,
  type AuthenticateParams,
  type ConnectParams,
  type DeviceId,
  type FedError,
  type FedRequest,
  type FedWireFrame,
  type HelloOk,
  type HostStateDigest,
  type KnownPeer,
  type PeerAnnouncement,
  type PeerIdentity,
  type PeerIdentityMaterial,
  type TrustApproveParams,
} from '../../fed-peer/lib/index.js'
import { AuditLog } from './audit.js'
import { HostRegistry } from './registry.js'

export interface GatewayConfig {
  port?: number
  /** Empty/absent = auto-detect the VPN interface, and refuse to listen if absent. */
  bindHost?: string
  auditPath?: string
  stateDir?: string
  /** Label this node advertises to peers. Display only. */
  nickname?: string
}

/** What a socket is allowed to do right now. Mirrors the handshake stage. */
type ConnKind = 'pending' | 'operator' | 'peer' | 'held'

interface ConnCtx {
  ws: WebSocket
  kind: ConnKind
  acceptor: AcceptorState
  identity?: PeerIdentity
  /** Audit label: nickname once known, else the socket's own description. */
  label: string
  outSeq: number
  ackedThrough: number
}

interface InFlightTask {
  taskId: string
  traceId: string
  deviceId: DeviceId
  timer: ReturnType<typeof setTimeout>
}

interface PendingUserReply {
  conn: ConnCtx
  reqId: string
  taskId: string
  traceId: string
  replayKey: string
}

/**
 * How often live sockets are reconciled with the trust table.
 *
 * Short enough that an operator's approval feels immediate, long enough that the
 * cost is irrelevant. Bounded on purpose rather than event-driven, because the
 * writer is a DIFFERENT process (the CLI) and there is no channel to notify
 * this one without inventing one.
 */
const TRUST_SYNC_INTERVAL_MS = 2_000

export class GatewayServer {
  readonly #cfg: Required<GatewayConfig>
  readonly #audit: AuditLog
  readonly #registry = new HostRegistry()
  readonly #trust: TrustTable
  readonly #peers: PeerTable
  readonly #identity: PeerIdentityMaterial
  readonly #conns = new Set<ConnCtx>()
  /** Live peer connections by deviceId — the dedupe and dispatch lookup. */
  readonly #peerConns = new Map<DeviceId, ConnCtx>()
  /** Peers that passed the handshake but await an operator's SAS confirmation. */
  readonly #held = new Map<DeviceId, ConnCtx>()
  readonly #tasks = new Map<string, InFlightTask>()
  readonly #idempotency = new Map<string, { res: unknown }>()
  readonly #pendingUserReplies = new Map<string, PendingUserReply>()
  readonly #userToken: string
  #wss: WebSocketServer | undefined
  #listening = false
  /** Reconciles live sockets with the trust table; see #syncTrust. */
  #trustTimer: ReturnType<typeof setInterval> | undefined

  constructor(config: GatewayConfig = {}) {
    const stateDir = config.stateDir ?? join(homedir(), '.hive')
    this.#cfg = {
      port: config.port ?? 3081,
      bindHost: config.bindHost ?? '',
      auditPath: config.auditPath ?? join(stateDir, 'audit.log'),
      stateDir,
      nickname: config.nickname ?? '',
    }
    mkdirSync(stateDir, { recursive: true })
    this.#audit = new AuditLog(this.#cfg.auditPath)
    const loaded = loadOrCreateIdentity(stateDir)
    this.#identity = loaded.identity
    if (loaded.created) console.log(`[hive] identity created: ${this.#identity.deviceId}`)
    this.#trust = new TrustTable(trustPersistenceFor(stateDir))
    this.#peers = new PeerTable(stateDir)
    // Local operator token: gates the loopback CLI only. It is NOT a federation
    // credential — no other machine can present it, so it needs no registry.
    const userTokenFile = join(stateDir, 'gateway-user-token')
    this.#userToken = existsSync(userTokenFile)
      ? readFileSync(userTokenFile, 'utf8').trim()
      : randomBytes(32).toString('base64url')
  }

  get identity(): { deviceId: DeviceId; nickname: string } {
    return { deviceId: this.#identity.deviceId, nickname: this.#cfg.nickname }
  }

  get userToken(): string {
    return this.#userToken
  }

  get listening(): boolean {
    return this.#listening
  }

  /** Operator-visible peers awaiting SAS confirmation. */
  pendingTrust(): readonly { deviceId: string; nickname: string; sas: string }[] {
    return this.#trust.pending().map((request) => ({ deviceId: request.deviceId, nickname: request.nickname, sas: request.sas }))
  }

  /**
   * Live peer rows for the operator surface. Read-only and derived: it exposes
   * what the registry already knows, never a trust decision.
   */
  peerStates(): readonly (HostStateDigest & { online: boolean })[] {
    return this.#registry.list()
  }

  /**
   * Start the listener.
   *
   * Fail-closed: with no explicit bindHost and no detectable VPN interface we do
   * NOT fall back to the LAN or to 0.0.0.0. Staying closed is the safe failure
   * (visible, and fixable by starting the VPN); silently widening exposure is
   * neither.
   */
  start(): void {
    const target = resolveListenTarget(this.#cfg.bindHost)
    if (target.mode === 'refused') {
      console.error(`[hive] listener NOT started: ${target.reason}`)
      console.error(`[hive] this node can still DIAL peers; it just cannot be dialed`)
      this.#listening = false
      return
    }
    const host = target.address
    this.#wss = new WebSocketServer({ port: this.#cfg.port, host })
    this.#wss.on('connection', (ws) => this.#onConnection(ws))
    this.#wss.on('error', (error) => console.error(`[hive] listener error: ${error.message}`))
    this.#logKnownPeers()
    if (this.#trustTimer === undefined) {
      // Cheap: two small maps plus one file read per tick.
      this.#trustTimer = setInterval(() => this.#syncTrust(), TRUST_SYNC_INTERVAL_MS)
    }
    this.#listening = true
    writeFileSync(join(this.#cfg.stateDir, 'gateway-user-token'), this.#userToken, 'utf8')
    console.log(`[hive] listening as ${this.#identity.deviceId} on ws://${host}:${this.#cfg.port}/fed` +
      (target.mode === 'vpn' ? ` (VPN interface ${target.iface})` : ' (explicit bindHost)'))
  }

  stop(): void {
    for (const task of this.#tasks.values()) clearTimeout(task.timer)
    if (this.#trustTimer !== undefined) clearInterval(this.#trustTimer)
    this.#trustTimer = undefined
    this.#wss?.close()
    for (const conn of this.#conns) conn.ws.terminate()
    this.#listening = false
  }

  /**
   * Reconcile live sockets with the trust table.
   *
   * The table is the SHARED MEDIUM, so an approval or a revocation may arrive
   * from the other process on this machine (the operator CLI writes the file
   * directly, deliberately, so it works even with dsh stopped). Polling is what
   * makes those decisions act on connections that are already open instead of
   * waiting for the peer to reconnect — and for revocation that is not a
   * nicety: leaving an already-authorized socket running would mean revoking a
   * peer only took effect on its next handshake.
   */
  #syncTrust(): void {
    for (const [deviceId, conn] of [...this.#held]) {
      if (!this.#trust.isTrusted(deviceId)) continue
      const step = acceptorOnTrustApproved(this.#deps(), conn.acceptor)
      if (!step.outcome.ok || step.outcome.step !== 'authenticated') continue
      this.#promoteToPeer(conn, step.outcome.hello)
      this.#send(conn, { type: 'event', event: FedEventCatalog.TRUST_GRANTED, payload: { deviceId: this.#identity.deviceId } })
      this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'trust.granted', target: String(deviceId), decision: 'allow' })
    }
    for (const [deviceId] of [...this.#peerConns]) {
      if (this.#trust.isTrusted(deviceId)) continue
      this.#dropPeer(deviceId, 'trust revoked')
    }
  }

  #onConnection(ws: WebSocket): void {
    const conn: ConnCtx = {
      ws,
      kind: 'pending',
      acceptor: newAcceptorState(),
      label: 'unidentified',
      outSeq: 0,
      ackedThrough: 0,
    }
    this.#conns.add(conn)
    ws.on('message', (data) => {
      let raw: unknown
      try {
        raw = JSON.parse(String(data))
      } catch {
        this.#replyError(conn, '?', fedError(FedErrorCode.PAYLOAD_INVALID, 'frames must be JSON'))
        return
      }
      try {
        this.#handleFrame(conn, decodeFrame(raw))
      } catch (error) {
        // A handler failure must NEVER escape the message loop: a thrown error
        // here would take the whole dsh process down with it. Report and go on.
        const err = toFedError(error)
        const rawId = raw !== null && typeof raw === 'object' && typeof (raw as Record<string, unknown>).id === 'string'
          ? (raw as Record<string, unknown>).id as string
          : '?'
        this.#replyError(conn, rawId, fedError(FedErrorCode.INTERNAL, err.message))
        this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'frame.error', target: 'listener', decision: 'deny', detail: err.message })
      }
    })
    ws.on('close', () => {
      this.#conns.delete(conn)
      if (conn.identity === undefined) return
      const deviceId = conn.identity.deviceId
      if (this.#peerConns.get(deviceId) !== conn) return
      this.#peerConns.delete(deviceId)
      this.#registry.unbind(deviceId)
      this.#broadcastToOperators({ type: 'event', event: FedEventCatalog.PRESENCE, payload: { deviceId, presence: 'offline' } })
    })
  }

  #handleFrame(conn: ConnCtx, frame: FedWireFrame): void {
    if (frame.type === 'event.ack') {
      conn.ackedThrough = frame.ackedThrough
      return
    }
    // A held peer may only negotiate trust; everything else waits for the
    // operator. Enforced here rather than per-method so a new method cannot
    // forget the check.
    if (frame.type === 'event') return

    if (frame.type === 'res') {
      const pending = this.#pendingUserReplies.get(frame.id)
      if (pending !== undefined) this.#relayPeerResult(conn, pending, frame.ok, frame.payload, frame.error)
      return
    }

    if (frame.method === FedMethod.CONNECT) return this.#handleConnect(conn, frame)
    if (frame.method === FedMethod.AUTHENTICATE) return this.#handleAuthenticate(conn, frame)
    if (conn.kind === 'pending') {
      this.#replyError(conn, frame.id, fedError(FedErrorCode.UNAUTHENTICATED, 'connect first'))
      return
    }
    if (conn.kind === 'held' && !frame.method.startsWith('trust.')) {
      this.#replyError(conn, frame.id, fedError(FedErrorCode.UNAUTHENTICATED, 'awaiting operator confirmation'))
      return
    }
    switch (frame.method) {
      case FedMethod.TRUST_PENDING_LIST: return this.#replyOk(conn, frame.id, { pending: this.pendingTrust() })
      case FedMethod.TRUST_APPROVE: return this.#handleTrustApprove(conn, frame)
      case FedMethod.TRUST_REVOKE: return this.#handleTrustRevoke(conn, frame)
      case FedMethod.TRUST_LIST: return this.#replyOk(conn, frame.id, { peers: this.#trust.list() })
      case FedMethod.HOST_LIST: return this.#replyOk(conn, frame.id, { peers: this.#registry.list() })
      case FedMethod.PEER_EXCHANGE: return this.#replyOk(conn, frame.id, { peers: this.#knownPeers() })
      case FedMethod.HOST_STATE_REPORT: return this.#handleStateReport(conn, frame)
      case FedMethod.AGENT_TASK: return this.#handleTaskDispatch(conn, frame)
      case FedMethod.AGENT_TASK_CANCEL: return this.#handleTaskCancel(conn, frame)
      default:
        this.#replyError(conn, frame.id, fedError(FedErrorCode.METHOD_UNKNOWN, `unknown method ${frame.method}`))
    }
  }

  /** Handshake inputs. One place, so the nickname cannot be forgotten at one call site. */
  #deps(): { identity: PeerIdentityMaterial; trust: TrustTable; selfNickname: string } {
    return { identity: this.#identity, trust: this.#trust, selfNickname: this.#cfg.nickname }
  }

  /**
   * Tear down a peer's live connection AND its registry row.
   *
   * Both halves matter. The close handler deliberately ignores sockets that are
   * no longer the current entry (so closing a replaced duplicate cannot unbind
   * the survivor) — which means anyone who removes the entry FIRST must unbind
   * here too, or the peer stays "online" in the operator's list forever.
   */
  #dropPeer(deviceId: DeviceId, reason: string): void {
    const conn = this.#peerConns.get(deviceId)
    this.#peerConns.delete(deviceId)
    this.#registry.unbind(deviceId)
    this.#broadcastToOperators({ type: 'event', event: FedEventCatalog.PRESENCE, payload: { deviceId, presence: 'offline' } })
    if (conn !== undefined) {
      this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'peer.drop', target: String(deviceId), decision: 'deny', detail: reason })
      conn.ws.close()
    }
  }

  #handleConnect(conn: ConnCtx, req: FedRequest): void {
    const params = req.params as { role?: string; userToken?: string } | undefined
    if (params?.role === 'user') {
      const presented = typeof params.userToken === 'string' ? params.userToken : ''
      if (!localTokenMatches(presented, this.#userToken)) {
        this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'connect.operator', target: 'listener', decision: 'deny', detail: 'bad local token' })
        this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, 'operator token required'))
        conn.ws.close()
        return
      }
      conn.kind = 'operator'
      conn.label = 'operator'
      this.#replyOk(conn, req.id, { protocol: 2, peer: { role: 'user', deviceId: this.#identity.deviceId, nickname: 'operator' }, serverTimeMs: Date.now(), trusted: true })
      return
    }
    if (params?.role !== 'host') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'role must be host | user'))
      return
    }
    const step = acceptorOnConnect(this.#deps(), conn.acceptor, req.params as ConnectParams | undefined)
    conn.acceptor = step.state
    if (!step.outcome.ok) {
      this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'handshake.connect', target: 'listener', decision: 'deny', detail: step.outcome.error.message })
      this.#replyError(conn, req.id, step.outcome.error)
      conn.ws.close()
      return
    }
    if (step.outcome.step !== 'challenge') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.INTERNAL, 'handshake did not produce a challenge'))
      return
    }
    conn.label = String(conn.acceptor.dialerNickname ?? 'peer')
    this.#replyOk(conn, req.id, step.outcome.challenge)
    this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'handshake.challenge', target: String(conn.acceptor.dialerId), decision: 'info', detail: { sas: conn.acceptor.sas } })
  }

  #handleAuthenticate(conn: ConnCtx, req: FedRequest): void {
    const step = acceptorOnAuthenticate(this.#deps(), conn.acceptor, req.params as AuthenticateParams | undefined)
    conn.acceptor = step.state
    if (!step.outcome.ok) {
      this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'handshake.authenticate', target: 'listener', decision: 'deny', detail: step.outcome.error.message })
      this.#replyError(conn, req.id, step.outcome.error)
      conn.ws.close()
      return
    }
    if (step.outcome.step !== 'authenticated') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.INTERNAL, 'handshake did not complete'))
      return
    }
    const hello = step.outcome.hello
    this.#replyOk(conn, req.id, hello)
    if (hello.trusted) this.#promoteToPeer(conn, hello)
    else this.#holdForTrust(conn, hello)
  }

  /** A held peer: identity proven, waiting on a human. */
  #holdForTrust(conn: ConnCtx, hello: HelloOk): void {
    conn.kind = 'held'
    conn.identity = this.#trust.lookup(hello.peer.deviceId, String(conn.acceptor.dialerPublicKey))
    this.#held.set(hello.peer.deviceId, conn)
    const request = this.#trust.pendingFor(hello.peer.deviceId)
    console.log(`[hive] peer ${hello.peer.nickname} (${hello.peer.deviceId}) awaits confirmation — SAS ${request?.sas ?? '?'}`)
    // Operators need the SAS on screen to compare it with the other machine.
    this.#broadcastToOperators({
      type: 'event',
      event: FedEventCatalog.TRUST_PENDING,
      payload: { deviceId: hello.peer.deviceId, nickname: hello.peer.nickname, sas: request?.sas ?? '' },
    })
    this.#audit.write({ ts: Date.now(), actor: hello.peer.nickname, action: 'trust.pending', target: hello.peer.deviceId, decision: 'info' })
  }

  #promoteToPeer(conn: ConnCtx, hello: HelloOk, peer?: PeerIdentity): void {
    const identity = peer ?? this.#trust.lookup(hello.peer.deviceId, String(conn.acceptor.dialerPublicKey))
    if (identity === undefined) {
      conn.ws.close()
      return
    }
    conn.kind = 'peer'
    conn.identity = identity
    conn.label = hello.peer.nickname

    // Duplicate resolution: both ends dial, so a pair can briefly hold two
    // sockets. Both sides run keepConnection over ids they already have and
    // therefore agree on which socket survives.
    const existing = this.#peerConns.get(identity.deviceId)
    if (existing !== undefined && existing !== conn && existing.ws.readyState === WebSocket.OPEN) {
      const keepNew = keepConnection(this.#identity.deviceId, identity.deviceId, true)
      if (!keepNew) {
        conn.ws.close()
        return
      }
      existing.ws.close()
    }
    this.#peerConns.set(identity.deviceId, conn)
    this.#held.delete(identity.deviceId)
    this.#registry.bind(identity, (frame) => this.#send(conn, frame as Record<string, unknown>))
    this.#broadcastToOperators({ type: 'event', event: FedEventCatalog.PRESENCE, payload: { deviceId: identity.deviceId, presence: 'online' } })
    this.#audit.write({ ts: Date.now(), actor: conn.label, action: 'handshake.ok', target: identity.deviceId, decision: 'allow' })
  }

  #handleTrustApprove(conn: ConnCtx, req: FedRequest): void {
    if (conn.kind !== 'operator') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, 'only the local operator surface approves peers'))
      return
    }
    const params = req.params as TrustApproveParams | undefined
    if (typeof params?.deviceId !== 'string' || typeof params?.sas !== 'string') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'trust.approve requires deviceId and sas'))
      return
    }
    const result = this.#trust.approve(params.deviceId as DeviceId, params.sas, { nickname: params.nickname })
    if (!result.ok) {
      this.#audit.write({ ts: Date.now(), actor: 'operator', action: 'trust.approve', target: params.deviceId, decision: 'deny', detail: result.reason })
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, `trust approval refused: ${result.reason}`))
      return
    }
    // Promote the held socket, if this operator decision unblocks one.
    const held = this.#held.get(params.deviceId as DeviceId)
    if (held !== undefined) {
      const step = acceptorOnTrustApproved(this.#deps(), held.acceptor)
      if (step.outcome.ok && step.outcome.step === 'authenticated') {
        this.#promoteToPeer(held, step.outcome.hello, result.peer)
        this.#send(held, { type: 'event', event: FedEventCatalog.TRUST_GRANTED, payload: { deviceId: this.#identity.deviceId } })
      }
    }
    this.#replyOk(conn, req.id, { deviceId: result.peer.deviceId, nickname: result.peer.displayName })
    this.#audit.write({ ts: Date.now(), actor: 'operator', action: 'trust.approve', target: result.peer.deviceId, decision: 'allow' })
  }

  #handleTrustRevoke(conn: ConnCtx, req: FedRequest): void {
    if (conn.kind !== 'operator') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, 'only the local operator surface revokes peers'))
      return
    }
    const deviceId = (req.params as { deviceId?: string } | undefined)?.deviceId
    if (typeof deviceId !== 'string') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'deviceId required'))
      return
    }
    const removed = this.#trust.revoke(deviceId as DeviceId)
    // A revoked peer must lose its live socket immediately AND leave the
    // operator's list: revocation that only takes effect on the next reconnect
    // is not revocation.
    if (this.#peerConns.has(deviceId as DeviceId)) this.#dropPeer(deviceId as DeviceId, 'trust revoked by operator')
    else this.#registry.unbind(deviceId as DeviceId)
    const held = this.#held.get(deviceId as DeviceId)
    if (held !== undefined) {
      this.#held.delete(deviceId as DeviceId)
      this.#send(held, { type: 'event', event: FedEventCatalog.TRUST_DENIED, payload: { deviceId: this.#identity.deviceId } })
      held.ws.close()
    }
    this.#replyOk(conn, req.id, { revoked: removed })
    this.#audit.write({ ts: Date.now(), actor: 'operator', action: 'trust.revoke', target: deviceId, decision: removed ? 'allow' : 'info' })
  }

  #knownPeers(): readonly PeerAnnouncement[] {
    const trusted = new Map(this.#trust.list().map((peer) => [peer.deviceId, peer]))
    return this.#peers.list().map((peer: KnownPeer) => ({
      deviceId: peer.deviceId,
      publicKey: peer.publicKey,
      nickname: peer.nickname,
      address: peer.address,
      trusted: trusted.has(peer.deviceId),
      lastSeenMs: peer.lastSeenMs,
    }))
  }

  /** Known-but-not-yet-trusted addresses are audit-visible at boot. */
  #logKnownPeers(): void {
    // Peer-table gossip is a hint only: an announced peer still has to pass a
    // full handshake and an operator's SAS check before it can do anything.
    for (const peer of this.#peers.list()) {
      if (peer.deviceId === this.#identity.deviceId) continue
      this.#audit.write({ ts: Date.now(), actor: 'listener', action: 'peer.known', target: peer.deviceId, decision: 'info', detail: { address: peer.address } })
    }
  }

  #handleStateReport(conn: ConnCtx, req: FedRequest): void {
    if (conn.kind !== 'peer' || conn.identity === undefined) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, 'peer identity required'))
      return
    }
    const raw = (req.params ?? {}) as Record<string, unknown>
    const digest: HostStateDigest = {
      deviceId: conn.identity.deviceId,
      // The peer's own label, self-reported. Cosmetic: dispatch and capability
      // checks all key off deviceId, so renaming grants nothing.
      nickname: typeof raw.nickname === 'string' && raw.nickname.length > 0 ? raw.nickname.slice(0, 64) : conn.identity.displayName,
      os: typeof raw.os === 'string' ? raw.os.slice(0, 64) : 'unknown',
      lanAddress: typeof raw.lanAddress === 'string' ? raw.lanAddress.slice(0, 64) : 'unknown',
      cpuLoadPct: typeof raw.cpuLoadPct === 'number' ? raw.cpuLoadPct : undefined,
      memTotalMb: typeof raw.memTotalMb === 'number' ? raw.memTotalMb : undefined,
      memFreeMb: typeof raw.memFreeMb === 'number' ? raw.memFreeMb : undefined,
      reportedAtMs: Date.now(),
    }
    this.#registry.touch(conn.identity.deviceId, digest)
    this.#replyOk(conn, req.id, { recorded: true })
    this.#broadcastToOperators({ type: 'event', event: FedEventCatalog.HOST_STATE, payload: digest })
  }

  #handleTaskDispatch(conn: ConnCtx, req: FedRequest): void {
    if (conn.kind !== 'operator') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, 'only the local operator surface dispatches tasks'))
      return
    }
    const params = (req.params ?? {}) as { peer?: string; prompt?: string; deadlineMs?: number; traceId?: string }
    if (typeof params.prompt !== 'string' || params.prompt.length === 0) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'prompt required'))
      return
    }
    if (typeof req.idempotencyKey !== 'string' || req.idempotencyKey.length === 0) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'agent.task requires idempotencyKey'))
      return
    }
    const replayKey = `${conn.label}:${req.idempotencyKey}`
    const replay = this.#idempotency.get(replayKey)
    if (replay !== undefined) {
      this.#replyOk(conn, req.id, replay.res)
      return
    }
    // Dispatch is restricted to operator-confirmed peers: the registry only
    // ever contains identities that came through a handshake + trust row, so
    // an unknown or revoked name resolves to nothing here.
    const target = this.#registry.findForDispatch(params.peer ?? '')
    if (target === undefined) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, `peer ${params.peer ?? '?'} is not available`))
      return
    }
    if (!this.#registry.hasCap(target.identity.deviceId, 'task.exec')) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, `peer ${target.identity.deviceId} was not granted task.exec`))
      return
    }
    const traceId = typeof params.traceId === 'string' && params.traceId.length > 0 ? params.traceId : `t-${Date.now()}-${randomBytes(3).toString('hex')}`
    const taskId = `task-${Date.now()}-${randomBytes(3).toString('hex')}`
    const deadlineMs = typeof params.deadlineMs === 'number' && params.deadlineMs > 0 ? params.deadlineMs : 30_000

    const timer = setTimeout(() => {
      if (this.#tasks.delete(taskId)) {
        this.#pendingUserReplies.delete(`gw-${taskId}`)
        this.#replyError(conn, req.id, fedError(FedErrorCode.DEADLINE_EXCEEDED, `task exceeded ${deadlineMs}ms`, { traceId }))
        this.#audit.write({ ts: Date.now(), traceId, actor: 'listener', action: 'agent.task', target: String(target.identity.deviceId), decision: 'deny', detail: 'deadline' })
      }
    }, deadlineMs)

    this.#tasks.set(taskId, { taskId, traceId, deviceId: target.identity.deviceId, timer })
    this.#pendingUserReplies.set(`gw-${taskId}`, { conn, reqId: req.id, taskId, traceId, replayKey })
    target.send?.({
      type: 'req',
      id: `gw-${taskId}`,
      method: FedMethod.AGENT_TASK,
      params: { taskId, prompt: params.prompt, requiredCaps: ['task.exec'], deadlineMs, traceId },
      deadlineMs: Date.now() + deadlineMs,
      idempotencyKey: req.idempotencyKey,
      traceId,
    })
    this.#audit.write({
      ts: Date.now(), traceId, actor: 'operator', action: 'agent.task',
      target: String(target.identity.deviceId), decision: 'allow', detail: { taskId, prompt: params.prompt.slice(0, 200) },
    })
  }

  #handleTaskCancel(conn: ConnCtx, req: FedRequest): void {
    const taskId = (req.params as { taskId?: string } | undefined)?.taskId
    const task = typeof taskId === 'string' ? this.#tasks.get(taskId) : undefined
    if (task === undefined) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, 'task not in flight'))
      return
    }
    // Send on the live peer socket. ConnCtx has no send of its own, so route
    // through #send rather than reaching for a method that is not there.
    const live = this.#peerConns.get(task.deviceId)
    if (live !== undefined) {
      this.#send(live, {
        type: 'req',
        id: `cancel-${task.taskId}`,
        method: FedMethod.AGENT_TASK_CANCEL,
        params: { taskId: task.taskId, traceId: task.traceId },
        traceId: task.traceId,
      })
    }
    this.#replyOk(conn, req.id, { cancelling: task.taskId })
    this.#audit.write({ ts: Date.now(), traceId: task.traceId, actor: 'operator', action: 'agent.task.cancel', target: task.taskId, decision: 'allow' })
  }

  /** Relay a peer's task result back to the operator surface that asked. */
  #relayPeerResult(conn: ConnCtx, pending: PendingUserReply, ok: boolean, payload: unknown, error: unknown): void {
    this.#pendingUserReplies.delete(`gw-${pending.taskId}`)
    const task = this.#tasks.get(pending.taskId)
    if (task !== undefined) {
      clearTimeout(task.timer)
      this.#tasks.delete(pending.taskId)
    }
    if (ok) {
      this.#idempotency.set(pending.replayKey, { res: payload })
      this.#replyOk(pending.conn, pending.reqId, payload)
    } else {
      this.#replyError(pending.conn, pending.reqId, toFedError(error, pending.traceId))
    }
    this.#audit.write({
      ts: Date.now(), traceId: pending.traceId, actor: conn.label,
      action: 'agent.task.result', target: pending.taskId, decision: ok ? 'allow' : 'deny',
    })
  }

  #replyOk(conn: ConnCtx, id: string, payload: unknown): void {
    this.#send(conn, { type: 'res', id, ok: true, payload })
  }

  #replyError(conn: ConnCtx, id: string, error: FedError): void {
    this.#send(conn, { type: 'res', id, ok: false, error })
  }

  #send(conn: ConnCtx, frame: Record<string, unknown>): void {
    if (frame.type === 'event') frame.seq = ++conn.outSeq
    if (conn.ws.readyState === WebSocket.OPEN) conn.ws.send(JSON.stringify(frame))
  }

  #broadcastToOperators(frame: Record<string, unknown>): void {
    for (const conn of this.#conns) {
      if (conn.kind === 'operator') this.#send(conn, { ...frame })
    }
  }
}
