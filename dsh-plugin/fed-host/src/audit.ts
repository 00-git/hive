/**
 * JSONL audit for host-side permission decisions (安全模型第 4 条：host 侧双写).
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
    if (file !== undefined) mkdirSync(dirname(file), { recursive: true })
  }

  write(entry: AuditEntry): void {
    const line = JSON.stringify(entry)
    if (this.#file !== undefined) {
      try {
        appendFileSync(this.#file, `${line}\n`, 'utf8')
      } catch {
        // Audit I/O must not break the task pipeline; console copy remains.
      }
    }
    console.log(`[hive-host-audit] ${line}`)
  }
}
