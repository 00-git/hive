/**
 * hive-fed-host client: gateway connection lifecycle.
 *
 * connect (token if stored) ??hello
 *   ??? ok            ??authenticated: register, report state, execute tasks
 *   ??? ok + pairing  ??pending: wait pair/result event, persist token, reconnect
 * Reconnect with exponential backoff + jitter; every decision audited.
 */
import { WebSocket } from 'ws'
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { freemem, homedir, hostname, platform, totalmem, uptime } from 'node:os'
import { join } from 'node:path'
import {
  FedCapability,
  FedErrorCode,
  FedEventCatalog,
  FedMethod,
  PROTOCOL_VERSION,
  decodeFrame,
  type FedRequest,
  type FedWireFrame,
} from '../../fed-protocol/lib/host/index.js'
import { AuditLog } from './audit.js'
import { runOp } from './ops.js'

export interface HostConfig {
  gatewayUrl?: string
  deviceName?: string
  /** Directory for the stored device token + audit log (defaults to ~/.hive). */
  stateDir?: string
  /** Directories fs.read may touch. Defaults to [process.cwd()]. */
  whitelistDirs?: readonly string[]
  stateIntervalMs?: number
}

interface StoredToken {
  deviceId: string
  token: string
  deviceName: string
}

interface PendingReply {
  resolve: (payload: unknown) => void
  reject: (error: unknown) => void
}

export class HostClient {
  readonly #cfg: Required<Omit<HostConfig, 'whitelistDirs'>> & { whitelistDirs: readonly string[] }
  readonly #audit: AuditLog
  #ws: WebSocket | undefined
  #attempt = 0
  #closedByUs = false
  #pending = new Map<string, PendingReply>()
  #stateTimer: ReturnType<typeof setInterval> | undefined

  constructor(config: HostConfig = {}) {
    const stateDir = config.stateDir ?? join(homedir(), '.hive')
    this.#cfg = {
      gatewayUrl: config.gatewayUrl ?? 'ws://127.0.0.1:3081/fed',
      deviceName: config.deviceName ?? hostname(),
      stateDir,
      stateIntervalMs: config.stateIntervalMs ?? 15_000,
      whitelistDirs: config.whitelistDirs ?? [process.cwd()],
    }
    this.#audit = new AuditLog(join(stateDir, 'host-audit.log'))
  }

  start(): void {
    this.#connect()
  }

  stop(): void {
    this.#closedByUs = true
    if (this.#stateTimer !== undefined) clearInterval(this.#stateTimer)
    this.#ws?.close()
  }

  #tokenFile(): string {
    return join(this.#cfg.stateDir, 'device-token.json')
  }

  #loadToken(): StoredToken | undefined {
    const file = this.#tokenFile()
    if (!existsSync(file)) return undefined
    try {
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as StoredToken
      if (typeof parsed.token === 'string' && typeof parsed.deviceId === 'string') return parsed
      return undefined
    } catch {
      return undefined
    }
  }

  #discardToken(): void {
    const file = this.#tokenFile()
    if (existsSync(file)) {
      try {
        const parsed = JSON.parse(readFileSync(file, 'utf8')) as StoredToken
        // Keep the audit trail; rename instead of delete.
        writeFileSync(`${file}.stale`, JSON.stringify(parsed, null, 2), 'utf8')
      } catch {
        // Ignore malformed stale files.
      }
      try {
        unlinkSync(file)
      } catch {
        // Windows file lock races are non-fatal here.
      }
    }
  }

  #saveToken(stored: StoredToken): void {
    mkdirSync(this.#cfg.stateDir, { recursive: true })
    writeFileSync(this.#tokenFile(), JSON.stringify(stored, null, 2), 'utf8')
  }

  #connect(): void {
    const stored = this.#loadToken()
    const ws = new WebSocket(this.#cfg.gatewayUrl)
    this.#ws = ws

    ws.on('open', () => {
      this.#attempt = 0
      const stored = this.#loadToken()
      this.#request(ws, FedMethod.CONNECT, {
        role: 'host',
        deviceName: this.#cfg.deviceName,
        protocol: { min: PROTOCOL_VERSION, max: PROTOCOL_VERSION },
        deviceToken: stored?.token,
        caps: Object.values(FedCapability),
      }).then((payload) => {
        const hello = payload as { protocol: number; pairing?: { code: string; expiresAtMs: number } }
        if (hello.pairing !== undefined) {
          console.log(`[hive-fed-host] pairing required: present code ${hello.pairing.code} to the operator`)
          this.#audit.write({ ts: Date.now(), actor: this.#cfg.deviceName, action: 'pair.wait', target: 'gateway', decision: 'info', detail: { code: hello.pairing.code } })
          return // stay connected; pair/result event decides the next step
        }
        if (stored !== undefined) this.#onAuthenticated(ws, stored)
      }).catch((error) => {
        const message = error instanceof Error ? error.message : JSON.stringify(error)
        console.error(`[hive-fed-host] connect rejected: ${message}`)
        if (message.includes('unauthenticated') && stored !== undefined) {
          // Self-heal: the gateway no longer knows this token (revoked/gateway
          // reset). Drop it and fall back to the pairing flow.
          this.#discardToken()
          this.#audit.write({ ts: Date.now(), actor: this.#cfg.deviceName, action: 'token.discard', target: 'gateway', decision: 'info' })
        }
        ws.close()
      })
    })

    ws.on('message', (data) => {
      let frame: FedWireFrame
      try {
        frame = decodeFrame(JSON.parse(String(data)))
      } catch (error) {
        this.#audit.write({ ts: Date.now(), actor: 'gateway', action: 'frame.invalid', target: 'host', decision: 'deny', detail: String(error) })
        return
      }
      if (frame.type === 'req') {
        this.#handleRequest(ws, frame)
        return
      }
      if (frame.type === 'res') {
        const pending = this.#pending.get(frame.id)
        if (pending !== undefined) {
          this.#pending.delete(frame.id)
          if (frame.ok) pending.resolve(frame.payload)
          else pending.reject(frame.error)
        }
        return
      }
      if (frame.type === 'event' && frame.event === FedEventCatalog.PAIR_RESULT) {
        const payload = frame.payload as { ok: boolean; token?: string; deviceId?: string; deviceName?: string }
        if (payload.ok === true && typeof payload.token === 'string' && typeof payload.deviceId === 'string') {
          this.#saveToken({ deviceId: payload.deviceId, token: payload.token, deviceName: payload.deviceName ?? this.#cfg.deviceName })
          this.#audit.write({ ts: Date.now(), actor: this.#cfg.deviceName, action: 'pair.approved', target: payload.deviceId, decision: 'allow' })
          console.log(`[hive-fed-host] paired as ${payload.deviceId} (${payload.deviceName}); reconnecting with token`)
          ws.close()
          setTimeout(() => this.#connect(), 300)
        }
      }
    })

    ws.on('close', () => {
      if (this.#closedByUs) return
      const delay = Math.min(30_000, 500 * 2 ** this.#attempt) + Math.floor(Math.random() * 250)
      this.#attempt += 1
      console.log(`[hive-fed-host] disconnected; reconnecting in ${delay}ms (attempt ${this.#attempt})`)
      setTimeout(() => this.#connect(), delay)
    })

    ws.on('error', (error) => {
      console.error(`[hive-fed-host] ws error: ${error.message}`)
    })
  }

  #onAuthenticated(ws: WebSocket, stored: StoredToken): void {
    console.log(`[hive-fed-host] authenticated as ${stored.deviceId} (${stored.deviceName})`)
    this.#audit.write({ ts: Date.now(), actor: this.#cfg.deviceName, action: 'connect.host', target: stored.deviceId, decision: 'allow' })
    void this.#request(ws, FedMethod.HOST_REGISTER, { digest: this.#stateDigest() }).catch(() => undefined)
    if (this.#stateTimer === undefined) {
      this.#stateTimer = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          void this.#request(ws, FedMethod.HOST_STATE_REPORT, { digest: this.#stateDigest() }).catch(() => undefined)
        }
      }, this.#cfg.stateIntervalMs)
    }
  }

  #stateDigest(): Record<string, unknown> {
    return {
      os: `${platform()} ${hostname()}`,
      lanAddress: 'loopback-mvp',
      memTotalMb: Math.round(totalmem() / 1024 / 1024),
      memFreeMb: Math.round(freemem() / 1024 / 1024),
      uptimeSec: Math.floor(uptime()),
    }
  }

  async #handleRequest(ws: WebSocket, req: FedRequest): Promise<void> {
    if (req.method === FedMethod.AGENT_TASK) {
      const params = (req.params ?? {}) as { taskId?: string; prompt?: string }
      const traceId = typeof req.traceId === 'string' ? req.traceId : undefined
      const deadlineHit = typeof req.deadlineMs === 'number' && Date.now() > req.deadlineMs
      if (deadlineHit) {
        this.#reply(ws, req.id, false, undefined, { code: FedErrorCode.DEADLINE_EXCEEDED, message: 'deadline already elapsed', traceId })
        return
      }
      try {
        const { op, args } = parsePromptSafe(typeof params.prompt === 'string' ? params.prompt : '')
        const result = await runOp(
          { whitelistDirs: this.#cfg.whitelistDirs, audit: this.#audit, maxReadBytes: 1_000_000 },
          traceId ?? '',
          op,
          args,
        )
        // Business denial (whitelist miss) is a SUCCESSFUL envelope carrying
        // ok:false inside ??only transport/protocol failures use ok:false here.
        this.#reply(ws, req.id, true, { taskId: params.taskId, ...result })
      } catch (error) {
        this.#reply(ws, req.id, false, undefined, { code: FedErrorCode.PAYLOAD_INVALID, message: error instanceof Error ? error.message : String(error), traceId })
      }
      return
    }
    if (req.method === FedMethod.AGENT_TASK_CANCEL) {
      // MVP ops complete quickly; cancel acknowledges and is audited.
      this.#audit.write({ ts: Date.now(), actor: 'gateway', action: 'task.cancel', target: JSON.stringify((req.params ?? {}).taskId ?? ''), decision: 'info' })
      this.#reply(ws, req.id, true, { cancelled: true })
      return
    }
    this.#reply(ws, req.id, false, undefined, { code: FedErrorCode.METHOD_UNKNOWN, message: `host does not mount ${req.method}` })
  }

  #reply(ws: WebSocket, id: string, ok: boolean, payload: unknown, error?: { code: string; message: string; traceId?: string }): void {
    ws.send(JSON.stringify({ type: 'res', id, ok, ...(ok ? { payload } : { error }) }))
  }

  #request(ws: WebSocket, method: string, params: unknown, extra?: { idempotencyKey?: string }): Promise<unknown> {
    const id = `h-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject })
      ws.send(JSON.stringify({ type: 'req', id, method, params, ...extra, traceId: `host-${Date.now()}` }))
    })
  }
}

function parsePromptSafe(prompt: string): { op: string; args: Record<string, unknown> } {
  // runOp's gate also rejects unknown ops; this parse only shapes the JSON.
  const parsed = JSON.parse(prompt) as { op?: unknown }
  if (typeof parsed !== 'object' || parsed === null || typeof parsed.op !== 'string') {
    throw new Error('prompt must be a JSON object with an op field')
  }
  const { op, ...rest } = parsed as Record<string, unknown>
  return { op, args: rest }
}
