/**
 * hive federation dialer — the OUTBOUND half of a hive node.
 *
 * A node dials every peer it knows and also listens (see the gateway half), so
 * the pair survives either side having the reachable address. Nothing here is
 * privileged: reaching a peer's port is not access, and an untouched trust row
 * is not trust.
 *
 * Trust is established per machine and confirmed by a human: the handshake
 * proves WHICH key is on the other end, and the operator decides whether that
 * key is acceptable by comparing six digits with the other machine's screen.
 */
import { WebSocket } from 'ws'
import { freemem, hostname, platform, totalmem, uptime } from 'node:os'
import { homedir } from 'node:os'
import { join } from 'node:path'
import {
  FedErrorCode,
  FedMethod,
  decodeFrame,
  type ChallengeOk,
  type DeviceId,
  type FedRequest,
  type FedWireFrame,
  type HelloOk,
  type PeerIdentityMaterial,
} from '../../fed-peer/lib/index.js'
import {
  dialerBuildConnect,
  dialerOnChallenge,
  dialerOnHello,
  loadOrCreateIdentity,
  newDialerState,
  trustPersistenceFor,
  PeerTable,
  TrustTable,
  type DialerState,
} from '../../fed-peer/lib/index.js'
import { AuditLog } from './audit.js'
import { runOp } from './ops.js'

export interface HostConfig {
  /** Peers to dial, as ws:// URLs. Comma-separated in the settings card. */
  peerUrls?: readonly string[]
  /** Label other machines display for this one. Display only. */
  nickname?: string
  /** Directory for identity, trust table, audit (defaults to ~/.hive). */
  stateDir?: string
  /** Directories fs.read may touch. Defaults to [process.cwd()]. */
  whitelistDirs?: readonly string[]
  stateIntervalMs?: number
}

interface Link {
  url: string
  ws: WebSocket
  dialer: DialerState
  /** Set once the challenge names the peer; used for dedupe and dispatch logs. */
  peerId?: DeviceId
  nickname: string
  /** True after hello.trusted; until then only handshake frames are exchanged. */
  ready: boolean
  /** What the ACCEPTOR said about us. A link needs both sides' consent. */
  peerTrustsUs: boolean
  attempt: number
}

interface PendingReply {
  resolve: (payload: unknown) => void
  reject: (error: unknown) => void
}

/**
 * How often links are re-checked against the trust table.
 *
 * The operator CLI approves by writing the shared file from another process, so
 * there is no callback on this side to hang the promotion off. Two seconds is
 * short enough that a confirmation feels immediate.
 */
const TRUST_SYNC_INTERVAL_MS = 2_000

export class HostClient {
  readonly #cfg: {
    peerUrls: readonly string[]
    nickname: string
    stateDir: string
    whitelistDirs: readonly string[]
    stateIntervalMs: number
  }
  readonly #audit: AuditLog
  readonly #identity: PeerIdentityMaterial
  readonly #trust: TrustTable
  readonly #peers: PeerTable
  readonly #links = new Map<string, Link>()
  readonly #pending = new Map<string, PendingReply>()
  #stateTimer: ReturnType<typeof setInterval> | undefined
  /** Promotes links once both operators have confirmed; see #syncTrust. */
  #trustTimer: ReturnType<typeof setInterval> | undefined
  #closedByUs = false

  constructor(config: HostConfig = {}) {
    const stateDir = config.stateDir ?? join(homedir(), '.hive')
    this.#cfg = {
      peerUrls: (config.peerUrls ?? []).filter((url) => url.length > 0),
      nickname: config.nickname ?? hostname(),
      stateDir,
      whitelistDirs: config.whitelistDirs ?? [process.cwd()],
      stateIntervalMs: config.stateIntervalMs ?? 15_000,
    }
    this.#audit = new AuditLog(join(stateDir, 'host-audit.log'))
    const loaded = loadOrCreateIdentity(stateDir)
    this.#identity = loaded.identity
    this.#trust = new TrustTable(trustPersistenceFor(stateDir))
    this.#peers = new PeerTable(stateDir)
    if (loaded.created) console.log(`[hive-fed-host] identity created: ${this.#identity.deviceId}`)
  }

  /** This node's own id — the value every peer will key its trust row off. */
  get deviceId(): DeviceId {
    return this.#identity.deviceId
  }

  /** Peers awaiting THIS machine's operator confirmation (the outbound half). */
  pendingTrust(): readonly { deviceId: string; nickname: string; sas: string }[] {
    return this.#trust.pending().map((request) => ({ deviceId: request.deviceId, nickname: request.nickname, sas: request.sas }))
  }

  start(): void {
    for (const url of this.#cfg.peerUrls) this.#dial(url)
    // Peers learned from gossip are dial candidates too; they still need a
    // handshake and an operator's confirmation before they can do anything.
    for (const peer of this.#peers.dialCandidates(this.#identity.deviceId)) {
      if (peer.address.startsWith('ws://') || peer.address.startsWith('wss://')) this.#dial(peer.address)
    }
    if (this.#stateTimer === undefined) {
      this.#stateTimer = setInterval(() => this.#reportState(), this.#cfg.stateIntervalMs)
    }
    if (this.#trustTimer === undefined) {
      this.#trustTimer = setInterval(() => this.#syncTrust(), TRUST_SYNC_INTERVAL_MS)
    }
  }

  stop(): void {
    this.#closedByUs = true
    if (this.#stateTimer !== undefined) clearInterval(this.#stateTimer)
    this.#stateTimer = undefined
    if (this.#trustTimer !== undefined) clearInterval(this.#trustTimer)
    this.#trustTimer = undefined
    for (const link of this.#links.values()) link.ws.close()
    this.#links.clear()
  }

  /**
   * Promote links that have BOTH confirmations.
   *
   * The operator CLI writes the trust file from another process, so this side
   * has no callback to hang the promotion off. Polling is the honest answer:
   * the file is the shared medium, and a link becomes usable the moment both
   * machines' operators have confirmed — not a heartbeat later than needed.
   */
  #syncTrust(): void {
    for (const link of this.#links.values()) {
      if (link.ready || link.peerId === undefined || !link.peerTrustsUs) continue
      if (link.dialer.stage !== 'ready') continue
      if (!this.#trust.isTrusted(link.peerId)) continue
      link.ready = true
      this.#trust.relabel(link.peerId, link.nickname)
      console.log(`[hive-fed-host] ${link.nickname} 双向确认完成，联邦链路已可用`)
      this.#audit.write({ ts: Date.now(), actor: this.#cfg.nickname, action: 'trust.granted', target: String(link.peerId), decision: 'allow' })
      this.#reportState()
    }
  }

  /** Handshake inputs. One place, so the nickname cannot be forgotten at one call site. */
  #deps(): { identity: PeerIdentityMaterial; trust: TrustTable; selfNickname: string } {
    return { identity: this.#identity, trust: this.#trust, selfNickname: this.#cfg.nickname }
  }

  #dial(url: string): void {
    if (this.#links.has(url)) return
    const ws = new WebSocket(url)
    const link: Link = { url, ws, dialer: newDialerState(), nickname: url, ready: false, peerTrustsUs: false, attempt: 0 }
    this.#links.set(url, link)

    ws.on('open', () => {
      link.attempt = 0
      const built = dialerBuildConnect(this.#deps(), link.dialer, {
        nickname: this.#cfg.nickname,
        caps: ['task.exec', 'task.ask', 'state.report'],
      })
      link.dialer = built.state
      this.#send(ws, 'hs-connect', FedMethod.CONNECT, built.params)
    })

    ws.on('message', (data) => {
      let frame: FedWireFrame
      try {
        frame = decodeFrame(JSON.parse(String(data)))
      } catch (error) {
        this.#audit.write({ ts: Date.now(), actor: link.url, action: 'frame.invalid', target: 'host', decision: 'deny', detail: String(error) })
        return
      }
      try {
        if (frame.type === 'req') {
          void this.#handleRequest(ws, frame)
          return
        }
        if (frame.type === 'res') {
          this.#handleResponse(link, frame.id, frame.ok, frame.payload, frame.error)
          return
        }
        if (frame.type === 'event') this.#handleEvent(link, frame.event, frame.payload)
      } catch (error) {
        // Never let a handler failure escape the message loop.
        console.error(`[hive-fed-host] frame handler failed: ${error instanceof Error ? error.message : String(error)}`)
      }
    })

    ws.on('close', () => {
      this.#links.delete(url)
      link.ready = false
      for (const [id, pending] of this.#pending) {
        // Fail in-flight requests instead of leaving callers waiting forever.
        pending.reject(new Error('connection closed'))
        this.#pending.delete(id)
      }
      if (this.#closedByUs) return
      const delay = Math.min(30_000, 1000 * 2 ** link.attempt) + Math.floor(Math.random() * 250)
      link.attempt += 1
      console.log(`[hive-fed-host] ${url} disconnected; redialing in ${delay}ms (attempt ${link.attempt})`)
      setTimeout(() => this.#dial(url), delay)
    })

    ws.on('error', (error) => {
      // Expected while the peer is down; the close handler schedules the retry.
      void error
    })
  }

  #send(ws: WebSocket, id: string, method: string, params: unknown, extra?: { idempotencyKey?: string }): void {
    if (ws.readyState !== WebSocket.OPEN) return
    ws.send(JSON.stringify({ type: 'req', id, method, params, ...extra, traceId: `host-${Date.now()}` }))
  }

  #handleResponse(link: Link, id: string, ok: boolean, payload: unknown, error: unknown): void {
    if (id === 'hs-connect') {
      if (!ok) {
        this.#failHandshake(link, error)
        return
      }
      const step = dialerOnChallenge(this.#deps(), link.dialer, payload as ChallengeOk)
      link.dialer = step.state
      if (!step.outcome.ok || step.outcome.step !== 'authenticate') {
        this.#failHandshake(link, step.outcome.ok ? new Error('peer answered with an unexpected step') : step.outcome.error)
        return
      }
      this.#send(link.ws, 'hs-auth', FedMethod.AUTHENTICATE, step.outcome.params)
      return
    }
    if (id === 'hs-auth') {
      if (!ok) {
        this.#failHandshake(link, error)
        return
      }
      const step = dialerOnHello(this.#deps(), link.dialer, payload as HelloOk)
      link.dialer = step.state
      if (!step.outcome.ok || step.outcome.step !== 'ready') {
        this.#failHandshake(link, step.outcome.ok ? new Error('peer answered with an unexpected step') : step.outcome.error)
        return
      }
      link.peerId = link.dialer.acceptorId
      link.nickname = step.outcome.nickname
      link.peerTrustsUs = step.outcome.peerTrustsUs
      // Both sides must consent: our operator confirmed the acceptor AND the
      // acceptor's operator confirmed us. One without the other is not a link.
      link.ready = step.outcome.trusted && step.outcome.peerTrustsUs
      if (link.peerId !== undefined) {
        this.#peers.upsert({ deviceId: link.peerId, publicKey: String(link.dialer.acceptorPublicKey), nickname: link.nickname, address: link.url, trusted: link.ready })
      }
      if (link.ready) {
        console.log(`[hive-fed-host] connected to ${link.nickname} (${String(link.peerId)})`)
        this.#audit.write({ ts: Date.now(), actor: this.#cfg.nickname, action: 'handshake.ok', target: String(link.peerId), decision: 'allow' })
        this.#reportState()
      } else {
        // Signature verified; a human still has to confirm. Report the SAS so
        // the operator can compare it with the other machine's screen.
        const sas = this.#trust.pendingFor(link.peerId as DeviceId)?.sas ?? link.dialer.sas ?? '?'
        console.log(`[hive-fed-host] ${link.nickname} (${String(link.peerId)}) needs confirmation on THIS machine — SAS ${sas}`)
        this.#audit.write({ ts: Date.now(), actor: this.#cfg.nickname, action: 'trust.pending', target: String(link.peerId), decision: 'info', detail: { sas } })
      }
      return
    }
    const pending = this.#pending.get(id)
    if (pending !== undefined) {
      this.#pending.delete(id)
      if (ok) pending.resolve(payload)
      else pending.reject(error)
    }
  }

  #failHandshake(link: Link, error: unknown): void {
    const message = error instanceof Error ? error.message : JSON.stringify(error)
    console.error(`[hive-fed-host] handshake with ${link.url} rejected: ${message}`)
    this.#audit.write({ ts: Date.now(), actor: this.#cfg.nickname, action: 'handshake', target: link.url, decision: 'deny', detail: message })
    // Do NOT retry immediately: a rejected handshake is usually a real mismatch
    // (wrong key, tampered frame), and hammering it buries the message.
    this.#links.delete(link.url)
    link.ws.close()
  }

  #handleEvent(link: Link, event: string, payload: unknown): void {
    if (event === 'trust/granted') {
      // The acceptor's operator just confirmed us. Our own side may still be
      // pending, so let the sweep decide rather than declaring the link up.
      link.peerTrustsUs = true
      if (this.#trust.isTrusted(link.peerId as DeviceId)) link.ready = true
      console.log(`[hive-fed-host] ${link.nickname} 已确认本机；${link.ready ? '链路已可用' : '本机还需确认对端'}`)
      this.#audit.write({ ts: Date.now(), actor: this.#cfg.nickname, action: 'trust.granted', target: String(link.peerId), decision: 'allow' })
      this.#reportState()
      return
    }
    void payload
  }

  #reportState(): void {
    const digest = {
      nickname: this.#cfg.nickname,
      os: `${platform()} ${hostname()}`,
      lanAddress: 'vpn',
      memTotalMb: Math.round(totalmem() / 1024 / 1024),
      memFreeMb: Math.round(freemem() / 1024 / 1024),
      uptimeSec: Math.floor(uptime()),
    }
    for (const link of this.#links.values()) {
      if (link.ready) this.#send(link.ws, `state-${Date.now()}`, FedMethod.HOST_STATE_REPORT, digest)
    }
  }

  async #handleRequest(ws: WebSocket, req: FedRequest): Promise<void> {
    if (req.method === FedMethod.AGENT_TASK) {
      const params = (req.params ?? {}) as { taskId?: string; prompt?: string }
      const traceId = typeof req.traceId === 'string' ? req.traceId : undefined
      if (typeof req.deadlineMs === 'number' && Date.now() > req.deadlineMs) {
        this.#reply(ws, req.id, false, undefined, { code: FedErrorCode.DEADLINE_EXCEEDED, message: 'deadline already elapsed', traceId })
        return
      }
      try {
        const parsed = JSON.parse(typeof params.prompt === 'string' ? params.prompt : '') as Record<string, unknown> | null
        if (parsed === null || typeof parsed !== 'object' || typeof parsed.op !== 'string') {
          throw new Error('prompt must be a JSON object with an op field')
        }
        const op: string = parsed.op
        const args: Record<string, unknown> = { ...parsed }
        delete args.op
        // The local permission gate runs here: a remote request is a REQUEST,
        // and the whitelist decision stays on this machine.
        const result = await runOp({ whitelistDirs: this.#cfg.whitelistDirs, audit: this.#audit, maxReadBytes: 1_000_000 }, traceId ?? '', op, args)
        // A business denial (whitelist miss) is a SUCCESSFUL envelope whose
        // payload says ok:false; transport-level failure is the only thing that
        // gets ok:false on the frame itself.
        this.#reply(ws, req.id, true, { taskId: params.taskId, ...result })
      } catch (error) {
        this.#reply(ws, req.id, false, undefined, { code: FedErrorCode.PAYLOAD_INVALID, message: error instanceof Error ? error.message : String(error), traceId })
      }
      return
    }
    if (req.method === FedMethod.AGENT_TASK_CANCEL) {
      this.#audit.write({ ts: Date.now(), actor: 'federation', action: 'task.cancel', target: String((req.params as { taskId?: string } | undefined)?.taskId ?? ''), decision: 'info' })
      this.#reply(ws, req.id, true, { cancelled: true })
      return
    }
    this.#reply(ws, req.id, false, undefined, { code: FedErrorCode.METHOD_UNKNOWN, message: `host does not mount ${req.method}` })
  }

  #reply(ws: WebSocket, id: string, ok: boolean, payload: unknown, error?: { code: string; message: string; traceId?: string }): void {
    if (ws.readyState !== WebSocket.OPEN) return
    ws.send(JSON.stringify({ type: 'res', id, ok, ...(ok ? { payload } : { error }) }))
  }
}
