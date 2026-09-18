/**
 * JSONL audit log — every cross-trust-boundary decision lands here.
 * 安全模型第 4 条：host 本地 session log + gateway 审计双写（本文件是 gateway 侧）。
 */
import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

export interface AuditEntry {
  ts: number
  traceId?: string
  actor: string
  action: string
  target: string
  decision: 'allow' | 'deny' | 'info'
  detail?: unknown
}

export class AuditLog {
  readonly #file: string | undefined

  constructor(file?: string) {
    this.#file = file
    if (file !== undefined) {
      mkdirSync(dirname(file), { recursive: true })
    }
  }

  write(entry: AuditEntry): void {
    const line = JSON.stringify(entry)
    if (this.#file !== undefined) {
      try {
        appendFileSync(this.#file, `${line}\n`, 'utf8')
      } catch {
        // Never let audit I/O kill the pipeline; the console copy below still lands.
      }
    }
    console.log(`[hive-audit] ${line}`)
  }
}
