/**
 * hive-fed-gateway server: role-based WS handshake (host | user), host registry,
 * pairing (code ??approve ??token, revocable), directed dispatch with
 * idempotency + deadlines + cancel, event seq/ack backpressure, JSONL audit
 * on every cross-trust-boundary decision.
 */
import { WebSocketServer, WebSocket } from 'ws'
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import {
  FedCapability,
  FedErrorCode,
  FedEventCatalog,
  FedMethod,
  decodeFrame,
  fedError,
  hashToken,
  issueDeviceToken,
  negotiateProtocol,
  toFedError,
  tokenHashesEqual,
  asDeviceToken,
  type DeviceId,
  type DeviceIdentity,
  type FedError,
  type FedRequest,
  type FedWireFrame,
} from '../../fed-protocol/lib/host/index.js'
import { AuditLog } from './audit.js'
import { PairingManager } from './pairing.js'
import { HostRegistry } from './registry.js'

export interface GatewayConfig {
  port?: number
  bindHost?: string
  auditPath?: string
  /** Directory for the gateway user token file (defaults to ~/.hive). */
  stateDir?: string
}

interface ConnCtx {
  ws: WebSocket
  role: 'pending-host' | 'host' | 'user'
  identity?: DeviceIdentity
  deviceName: string
  /** event seq counter for frames we send to this connection. */
  outSeq: number
  /** highest contiguous acked seq received from this connection. */
  ackedThrough: number
  /** pairing code this connection opened (pending hosts only). */
  pairCode?: string
}

interface InFlightTask {
  taskId: string
  traceId: string
  hostDeviceId: DeviceId
  timer: ReturnType<typeof setTimeout>
}

interface PendingUserReply {
  conn: ConnCtx
  reqId: string
  taskId: string
  traceId: string
  replayKey: string
}

export class GatewayServer {
  readonly #cfg: Required<GatewayConfig>
  readonly #audit: AuditLog
  readonly #registry = new HostRegistry()
  readonly #pairing = new PairingManager()
  readonly #conns = new Set<ConnCtx>()
  readonly #tasks = new Map<string, InFlightTask>()
  readonly #idempotency = new Map<string, { res: unknown }>()
  readonly #pendingUserReplies = new Map<string, PendingUserReply>()
  readonly #userToken: string
  #wss: WebSocketServer | undefined

  constructor(config: GatewayConfig = {}) {
    const stateDir = config.stateDir ?? join(homedir(), '.hive')
    this.#cfg = {
      port: config.port ?? 3081,
      bindHost: config.bindHost ?? '127.0.0.1',
      auditPath: config.auditPath ?? join(stateDir, 'audit.log'),
      stateDir,
    }
    this.#audit = new AuditLog(this.#cfg.auditPath)
    // ??????: the user surface also authenticates with an explicit token.
    // Loopback binding is transport hardening, never the authorization itself.
    // D-013: the user token PERSISTS across restarts (stable web-UI URL).
    const userTokenFile = join(stateDir, 'gateway-user-token')
    this.#userToken = existsSync(userTokenFile)
      ? readFileSync(userTokenFile, 'utf8').trim()
      : issueDeviceToken('gateway-user' as DeviceId).token
    // D-013: device registry persists (token hashes only) across restarts.
    this.#registry.setPersistence(join(stateDir, 'device-registry.json'))
  }

  get userToken(): string {
    return this.#userToken
  }

  start(): void {
    this.#wss = new WebSocketServer({ port: this.#cfg.port, host: this.#cfg.bindHost })
    this.#wss.on('connection', (ws) => this.#onConnection(ws))
    this.#wss.on('error', (error) => {
      console.error(`[hive-fed-gateway] server error: ${error.message}`)
    })
    this.#wss.on('close', () => {
      console.error('[hive-fed-gateway] server CLOSED (unexpected unless stop())')
    })
    writeUserTokenFile(this.#cfg.stateDir, this.#userToken)
    console.log(`[hive-fed-gateway] listening on ws://${this.#cfg.bindHost}:${this.#cfg.port}/fed pid=${process.pid}`)
    console.log(`[hive-fed-gateway] user token file: ${join(this.#cfg.stateDir, 'gateway-user-token')}`)
  }

  stop(): void {
    for (const task of this.#tasks.values()) clearTimeout(task.timer)
    this.#wss?.close()
    for (const conn of this.#conns) conn.ws.terminate()
  }

  #onConnection(ws: WebSocket): void {
    const conn: ConnCtx = { ws, role: 'pending-host', deviceName: 'unidentified', outSeq: 0, ackedThrough: 0 }
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
        const frame = decodeFrame(raw)
        this.#handleFrame(conn, frame)
      } catch (error) {
        // Handler failures must NEVER escape the message loop (a throw here
        // would crash the whole dsh process). Reply with the inbound id when
        // it is recoverable from the raw frame.
        const err = toFedError(error)
        const rawId = (raw !== null && typeof raw === 'object' && typeof (raw as Record<string, unknown>).id === 'string')
          ? (raw as Record<string, unknown>).id as string
          : '?'
        this.#replyError(conn, rawId, fedError(FedErrorCode.INTERNAL, err.message))
        this.#audit.write({
          ts: Date.now(), actor: conn.deviceName, action: 'frame.error', target: 'gateway', decision: 'deny', detail: err.message,
        })
      }
    })
    ws.on('close', () => {
      this.#conns.delete(conn)
      if (conn.role === 'host' && conn.identity !== undefined) {
        this.#registry.unbind(conn.identity.deviceId)
        this.#broadcastToUsers({
          type: 'event', event: FedEventCatalog.PRESENCE,
          payload: { deviceId: conn.identity.deviceId, presence: 'offline' },
        })
      }
    })
  }

  #handleFrame(conn: ConnCtx, frame: FedWireFrame): void {
    if (frame.type === 'event.ack') {
      conn.ackedThrough = frame.ackedThrough
      return
    }
    if (frame.type === 'event') return // peers do not push unsolicited events in MVP

    if (frame.type === 'res') {
      // Host replies to a forwarded agent.task/cancel ??relay to the initiator.
      const pending = this.#pendingUserReplies.get(frame.id)
      if (pending !== undefined) {
        const asReq = { ...frame, method: FedMethod.AGENT_TASK } as unknown as FedRequest
        this.#relayHostResult(conn, asReq, frame.ok, frame.payload, frame.error)
      }
      return
    }

    if (frame.method === FedMethod.CONNECT) {
      this.#handleConnect(conn, frame)
      return
    }
    if (conn.role === 'pending-host') {
      this.#replyError(conn, frame.id, fedError(FedErrorCode.UNAUTHENTICATED, 'connect first'))
      return
    }
    switch (frame.method) {
      case FedMethod.PAIR_APPROVE: return this.#handlePairApprove(conn, frame)
      case FedMethod.HOST_LIST: return this.#replyOk(conn, frame.id, { hosts: this.#registry.list() })
      case FedMethod.AGENT_TASK: return this.#handleTaskDispatch(conn, frame)
      case FedMethod.AGENT_TASK_CANCEL: return this.#handleTaskCancel(conn, frame)
      case FedMethod.HOST_STATE_REPORT: return this.#handleHostReport(conn, frame)
      default:
        this.#replyError(conn, frame.id, fedError(FedErrorCode.METHOD_UNKNOWN, `unknown method ${frame.method}`))
    }
  }

  #handleConnect(conn: ConnCtx, req: FedRequest): void {
    const params = (req.params ?? {}) as {
      role?: string
      deviceName?: string
      protocol?: { min: number; max: number }
      deviceToken?: string
      caps?: string[]
    }
    if (params.role !== 'host' && params.role !== 'user') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'role must be host | user'))
      return
    }
    try {
      negotiateProtocol({ role: params.role, deviceName: params.deviceName ?? '', protocol: params.protocol ?? { min: 1, max: 1 } })
    } catch (error) {
      this.#replyError(conn, req.id, error as FedError)
      return
    }
    conn.deviceName = typeof params.deviceName === 'string' && params.deviceName.length > 0
      ? params.deviceName.slice(0, 64)
      : 'unidentified'

    if (params.role === 'user') {
      const presented = typeof params.deviceToken === 'string' ? params.deviceToken : ''
      if (!tokenMatches(presented, this.#userToken)) {
        this.#audit.write({ ts: Date.now(), actor: conn.deviceName, action: 'connect.user', target: 'gateway', decision: 'deny', detail: 'bad user token' })
        this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, 'user token required'))
        conn.ws.close()
        return
      }
      conn.role = 'user'
      this.#replyOk(conn, req.id, { protocol: 1, peer: { role: 'user', deviceName: conn.deviceName }, serverTimeMs: Date.now() })
      this.#audit.write({ ts: Date.now(), actor: conn.deviceName, action: 'connect.user', target: 'gateway', decision: 'allow' })
      return
    }

    // host role with a token ??resolve identity through the hash-only store.
    const token = asDeviceToken(params.deviceToken)
    if (token !== undefined) {
      const identity = this.#registry.resolve(token)
      if (identity === undefined) {
        this.#audit.write({ ts: Date.now(), actor: conn.deviceName, action: 'connect.host', target: 'gateway', decision: 'deny', detail: 'unknown or revoked token' })
        this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, 'unknown or revoked device token'))
        conn.ws.close()
        return
      }
      conn.role = 'host'
      conn.identity = identity
      this.#registry.bind(identity, (frame) => this.#send(conn, frame))
      this.#replyOk(conn, req.id, { protocol: 1, peer: { role: 'host', deviceName: identity.displayName }, serverTimeMs: Date.now() })
      this.#broadcastToUsers({ type: 'event', event: FedEventCatalog.PRESENCE, payload: { deviceId: identity.deviceId, presence: 'online' } })
      this.#audit.write({ ts: Date.now(), actor: identity.displayName, action: 'connect.host', target: identity.deviceId, decision: 'allow' })
      return
    }

    // Unauthenticated host: open a pairing session and hand back the code.
    const pending = this.#pairing.create(conn.deviceName, Array.isArray(params.caps) ? params.caps : [])
    conn.role = 'pending-host'
    conn.pairCode = pending.code
    this.#replyOk(conn, req.id, {
      protocol: 1,
      peer: { role: 'host', deviceName: conn.deviceName },
      serverTimeMs: Date.now(),
      pairing: { code: pending.code, expiresAtMs: pending.expiresAtMs },
    })
    this.#broadcastToUsers({ type: 'event', event: FedEventCatalog.PAIR_PENDING, payload: { code: pending.code, deviceName: pending.deviceName, expiresAtMs: pending.expiresAtMs } })
    console.log(`[hive-fed-gateway] pairing pending: code ${pending.code} for "${pending.deviceName}"`)
    this.#audit.write({ ts: Date.now(), actor: conn.deviceName, action: 'pair.request', target: 'gateway', decision: 'info', detail: { code: pending.code } })
  }

  #handlePairApprove(conn: ConnCtx, req: FedRequest): void {
    const params = (req.params ?? {}) as { code?: string }
    if (conn.role !== 'user') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, 'only user surfaces approve pairings'))
      return
    }
    const result = this.#pairing.approve(typeof params.code === 'string' ? params.code : '', conn.deviceName)
    if (!result.ok) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, result.reason))
      this.#audit.write({ ts: Date.now(), actor: conn.deviceName, action: 'pair.approve', target: params.code ?? '?', decision: 'deny', detail: result.reason })
      return
    }
    const deviceId = this.#registry.mintDeviceId()
    const issued = issueDeviceToken(deviceId)
    const identity: DeviceIdentity = {
      deviceId,
      displayName: result.pending.deviceName,
      caps: result.pending.caps.filter(isKnownCap),
      pairedAt: Date.now(),
    }
    this.#registry.registerToken(deviceId, issued.token, identity)
    for (const other of this.#conns) {
      if (other.role === 'pending-host' && other.pairCode === result.pending.code) {
        this.#send(other, {
          type: 'event', event: FedEventCatalog.PAIR_RESULT,
          payload: { ok: true, token: issued.token, deviceId, deviceName: identity.displayName },
        })
        break
      }
    }
    this.#replyOk(conn, req.id, { deviceId, deviceName: identity.displayName, caps: identity.caps })
    this.#audit.write({ ts: Date.now(), actor: conn.deviceName, action: 'pair.approve', target: deviceId, decision: 'allow', detail: { deviceName: identity.displayName, caps: identity.caps } })
  }

  #handleHostReport(conn: ConnCtx, req: FedRequest): void {
    if (conn.role !== 'host' || conn.identity === undefined) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, 'host identity required'))
      return
    }
    const rawDigest = (req.params ?? {}) as Record<string, unknown>
    const digest = {
      deviceId: conn.identity.deviceId,
      displayName: conn.identity.displayName,
      os: typeof rawDigest.os === 'string' ? rawDigest.os.slice(0, 64) : 'unknown',
      lanAddress: typeof rawDigest.lanAddress === 'string' ? rawDigest.lanAddress.slice(0, 64) : 'unknown',
      cpuLoadPct: typeof rawDigest.cpuLoadPct === 'number' ? rawDigest.cpuLoadPct : undefined,
      memTotalMb: typeof rawDigest.memTotalMb === 'number' ? rawDigest.memTotalMb : undefined,
      memFreeMb: typeof rawDigest.memFreeMb === 'number' ? rawDigest.memFreeMb : undefined,
      reportedAtMs: Date.now(),
    }
    this.#registry.touch(conn.identity.deviceId, digest)
    this.#replyOk(conn, req.id, { recorded: true })
    this.#broadcastToUsers({ type: 'event', event: FedEventCatalog.HOST_STATE, payload: digest })
  }

  #handleTaskDispatch(conn: ConnCtx, req: FedRequest): void {
    if (conn.role !== 'user') {
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, 'only user surfaces dispatch tasks'))
      return
    }
    const params = (req.params ?? {}) as { host?: string; prompt?: string; deadlineMs?: number; traceId?: string }
    if (typeof params.prompt !== 'string' || params.prompt.length === 0) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'prompt required'))
      return
    }
    if (typeof req.idempotencyKey !== 'string' || req.idempotencyKey.length === 0) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, 'agent.task requires idempotencyKey'))
      return
    }
    const replayKey = `${conn.deviceName}:${req.idempotencyKey}`
    const replay = this.#idempotency.get(replayKey)
    if (replay !== undefined && replay.res !== undefined) {
      this.#replyOk(conn, req.id, replay.res)
      return
    }
    const target = this.#registry.findForDispatch(params.host ?? '')
    if (target === undefined) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, `host ${params.host ?? '?'} not online`))
      return
    }
    if (!this.#registry.hasCap(target.identity.deviceId, FedCapability.TASK_EXEC)) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, `host ${target.identity.displayName} lacks task.exec`))
      return
    }
    const traceId = typeof params.traceId === 'string' && params.traceId.length > 0
      ? params.traceId
      : `t-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const deadlineMs = typeof params.deadlineMs === 'number' && params.deadlineMs > 0 ? params.deadlineMs : 30_000

    const timer = setTimeout(() => {
      if (this.#tasks.delete(taskId)) {
        this.#pendingUserReplies.delete(`gw-${taskId}`)
        this.#replyError(conn, req.id, fedError(FedErrorCode.DEADLINE_EXCEEDED, `task exceeded ${deadlineMs}ms`, { traceId }))
        this.#audit.write({ ts: Date.now(), traceId, actor: 'gateway', action: 'agent.task', target: target.identity.displayName, decision: 'deny', detail: 'deadline' })
      }
    }, deadlineMs)

    this.#tasks.set(taskId, { taskId, traceId, hostDeviceId: target.identity.deviceId, timer })
    this.#pendingUserReplies.set(`gw-${taskId}`, { conn, reqId: req.id, taskId, traceId, replayKey })
    target.send({
      type: 'req',
      id: `gw-${taskId}`,
      method: FedMethod.AGENT_TASK,
      params: { taskId, prompt: params.prompt, requiredCaps: [FedCapability.TASK_EXEC], deadlineMs, traceId },
      deadlineMs: Date.now() + deadlineMs,
      idempotencyKey: req.idempotencyKey,
      traceId,
    })
    this.#audit.write({
      ts: Date.now(), traceId, actor: conn.deviceName, action: 'agent.task',
      target: target.identity.displayName, decision: 'allow', detail: { taskId, prompt: params.prompt.slice(0, 200) },
    })
  }

  #handleTaskCancel(conn: ConnCtx, req: FedRequest): void {
    const params = (req.params ?? {}) as { taskId?: string }
    const task = typeof params.taskId === 'string' ? this.#tasks.get(params.taskId) : undefined
    if (task === undefined) {
      this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, 'task not in flight'))
      return
    }
    const hostConn = [...this.#conns].find((c) => c.identity?.deviceId === task.hostDeviceId)
    hostConn?.send({
      type: 'req',
      id: `cancel-${task.taskId}`,
      method: FedMethod.AGENT_TASK_CANCEL,
      params: { taskId: task.taskId, traceId: task.traceId },
      traceId: task.traceId,
    })
    this.#replyOk(conn, req.id, { cancelling: task.taskId })
    this.#audit.write({ ts: Date.now(), traceId: task.traceId, actor: conn.deviceName, action: 'agent.task.cancel', target: task.taskId, decision: 'allow' })
  }

  /** Relay a host's task result back to the initiating user surface. */
  #relayHostResult(conn: ConnCtx, req: FedRequest, ok: boolean, payload: unknown, error: unknown): void {
    const pending = this.#pendingUserReplies.get(req.id)
    if (pending === undefined) return
    this.#pendingUserReplies.delete(req.id)
    const task = this.#tasks.get(pending.taskId)
    if (task !== undefined) {
      clearTimeout(task.timer)
      this.#tasks.delete(pending.taskId)
    }
    if (ok) this.#idempotency.set(pending.replayKey, { res: payload })
    if (ok) this.#replyOk(pending.conn, pending.reqId, payload)
    else this.#replyError(pending.conn, pending.reqId, toFedError(error, pending.traceId))
    this.#audit.write({
      ts: Date.now(), traceId: pending.traceId, actor: conn.identity?.displayName ?? 'host',
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

  #broadcastToUsers(frame: Record<string, unknown>): void {
    for (const conn of this.#conns) {
      if (conn.role === 'user') this.#send(conn, { ...frame })
    }
  }
}

function isKnownCap(value: string): value is FedCapability {
  return (Object.values(FedCapability) as string[]).includes(value)
}

/** Constant-time comparison over SHA-256 hashes (never raw secrets). */
function tokenMatches(presented: string, expected: string): boolean {
  return tokenHashesEqual(hashToken(presented as never), hashToken(expected as never))
}

function writeUserTokenFile(stateDir: string, token: string): void {
  mkdirSync(stateDir, { recursive: true })
  writeFileSync(join(stateDir, 'gateway-user-token'), token, 'utf8')
}
