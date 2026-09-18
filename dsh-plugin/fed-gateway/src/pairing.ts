/**
 * Pairing sessions: 6-digit codes, 5-minute TTL, 3 wrong approvals lock the
 * operator session for 60s (C ?????????user ?????.
 */
import { randomInt } from 'node:crypto'
import type { DeviceId } from '../../fed-protocol/lib/host/index.js'

export interface PendingPairing {
  code: string
  deviceName: string
  caps: readonly string[]
  createdAtMs: number
  expiresAtMs: number
}

export interface ApprovedPairing {
  deviceId: DeviceId
  token: string
  deviceName: string
}

const CODE_TTL_MS = 5 * 60_000
const MAX_WRONG_ATTEMPTS = 3
const LOCKOUT_MS = 60_000

export class PairingManager {
  readonly #pending = new Map<string, PendingPairing>()
  readonly #wrongAttempts = new Map<string, { count: number; lockedUntil: number }>()

  /** Create a pending pairing for an unauthenticated host connection. */
  create(deviceName: string, caps: readonly string[]): PendingPairing {
    // Purge expired first so codes stay unique while pending set is small.
    const now = Date.now()
    for (const [code, pending] of this.#pending) {
      if (pending.expiresAtMs <= now) this.#pending.delete(code)
    }
    let code = ''
    do {
      code = String(randomInt(0, 1_000_000)).padStart(6, '0')
    } while (this.#pending.has(code))
    const pending: PendingPairing = {
      code,
      deviceName,
      caps,
      createdAtMs: now,
      expiresAtMs: now + CODE_TTL_MS,
    }
    this.#pending.set(code, pending)
    return pending
  }

  /** Operator approves a code. Returns undefined + reason when rejected. */
  approve(code: string, operatorKey: string): { ok: true; pending: PendingPairing } | { ok: false; reason: string; lockedForMs?: number } {
    const now = Date.now()
    const attempts = this.#wrongAttempts.get(operatorKey)
    if (attempts !== undefined && attempts.lockedUntil > now) {
      return { ok: false, reason: 'approval attempts locked', lockedForMs: attempts.lockedUntil - now }
    }
    const pending = this.#pending.get(code)
    if (pending === undefined || pending.expiresAtMs <= now) {
      this.#recordWrong(operatorKey, now)
      return { ok: false, reason: 'unknown or expired pairing code' }
    }
    this.#pending.delete(code)
    this.#wrongAttempts.delete(operatorKey)
    return { ok: true, pending }
  }

  #recordWrong(operatorKey: string, now: number): void {
    const attempts = this.#wrongAttempts.get(operatorKey) ?? { count: 0, lockedUntil: 0 }
    attempts.count += 1
    if (attempts.count >= MAX_WRONG_ATTEMPTS) {
      attempts.lockedUntil = now + LOCKOUT_MS
      attempts.count = 0
    }
    this.#wrongAttempts.set(operatorKey, attempts)
  }

  get pendingCount(): number {
    return this.#pending.size
  }
}
