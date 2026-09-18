/**
 * Host-side task operations with the local permission gate.
 *
 * MVP op set (no LLM required for the acceptance path):
 *   echo    — trivial loopback proof
 *   fs.read — file read, gated by a directory whitelist (read-level cap)
 *   sysinfo — OS/memory digest (read-level cap)
 *
 * Permission semantics: whitelist pass = allow; anything else = deny with an
 * audited reason. Approval-rate-limit integration lands with fed-webui (第二步).
 */
import { readFile, stat } from 'node:fs/promises'
import { cpus, hostname, platform, totalmem, freemem, uptime, release } from 'node:os'
import { isAbsolute, normalize, resolve, sep } from 'node:path'
import { AuditLog } from './audit.js'

export interface OpsConfig {
  whitelistDirs: readonly string[]
  audit: AuditLog
  maxReadBytes?: number
}

export interface OpResult {
  ok: boolean
  op: string
  result?: unknown
  denied?: string
}

/** Parse the task prompt as a structured op. MVP contract, documented in README. */
export function parsePrompt(prompt: string): { op: string; args: Record<string, unknown> } {
  let parsed: unknown
  try {
    parsed = JSON.parse(prompt)
  } catch {
    throw new Error('prompt must be a JSON object: {"op":"echo"|"fs.read"|"sysinfo", ...}')
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('prompt must be a JSON object')
  }
  const record = parsed as Record<string, unknown>
  if (typeof record.op !== 'string') {
    throw new Error('prompt.op must be a string')
  }
  const { op, ...rest } = record
  return { op, args: rest }
}

export async function runOp(config: OpsConfig, traceId: string, op: string, args: Record<string, unknown>): Promise<OpResult> {
  switch (op) {
    case 'echo': {
      config.audit.write({ ts: Date.now(), traceId, actor: 'gateway', action: 'op.echo', target: 'self', decision: 'allow' })
      return { ok: true, op, result: { message: String(args.message ?? '') } }
    }
    case 'sysinfo': {
      config.audit.write({ ts: Date.now(), traceId, actor: 'gateway', action: 'op.sysinfo', target: 'self', decision: 'allow' })
      return {
        ok: true,
        op,
        result: {
          hostname: hostname(),
          platform: `${platform()} ${release()}`,
          uptimeSec: Math.floor(uptime()),
          cpuCount: cpus().length,
          memTotalMb: Math.round(totalmem() / 1024 / 1024),
          memFreeMb: Math.round(freemem() / 1024 / 1024),
        },
      }
    }
    case 'fs.read': return fsRead(config, traceId, args)
    default:
      config.audit.write({ ts: Date.now(), traceId, actor: 'gateway', action: `op.${op}`, target: 'self', decision: 'deny', detail: 'unknown op' })
      return { ok: false, op, denied: `unknown op ${op}` }
  }
}

async function fsRead(config: OpsConfig, traceId: string, args: Record<string, unknown>): Promise<OpResult> {
  const rawPath = typeof args.path === 'string' ? args.path : ''
  if (rawPath.length === 0) {
    return { ok: false, op: 'fs.read', denied: 'path required' }
  }
  const absolute = normalize(isAbsolute(rawPath) ? rawPath : resolve(process.cwd(), rawPath))
  const allowed = config.whitelistDirs.some((dir) => {
    const normalized = normalize(resolve(dir))
    return absolute === normalized || absolute.startsWith(normalized + sep)
  })
  if (!allowed) {
    config.audit.write({ ts: Date.now(), traceId, actor: 'gateway', action: 'op.fs.read', target: absolute, decision: 'deny', detail: 'outside whitelist' })
    return { ok: false, op: 'fs.read', denied: `path outside whitelist: ${absolute}` }
  }
  try {
    const info = await stat(absolute)
    if (info.isDirectory()) {
      return { ok: false, op: 'fs.read', denied: 'path is a directory' }
    }
    const maxBytes = config.maxReadBytes ?? 1_000_000
    if (info.size > maxBytes) {
      return { ok: false, op: 'fs.read', denied: `file larger than ${maxBytes} bytes` }
    }
    const content = await readFile(absolute, 'utf8')
    config.audit.write({ ts: Date.now(), traceId, actor: 'gateway', action: 'op.fs.read', target: absolute, decision: 'allow', detail: { bytes: info.size } })
    return { ok: true, op: 'fs.read', result: { path: absolute, bytes: info.size, content } }
  } catch (error) {
    return { ok: false, op: 'fs.read', denied: `read failed: ${error instanceof Error ? error.message : String(error) }` }
  }
}
