/**
 * Structured federation error codes and error payloads.
 *
 * Error semantics are A-class benchmarked against dsh tool-call error structure:
 * a stable code discriminant plus human-readable detail, machine-usable fields
 * (retryAfterMs) kept separate from prose. Codes are security invariants —
 * fixed set, never configurable (AGENTS.md: protocol constants stay fixed).
 */

/** Stable wire error codes. Closed set: add only with a protocol version bump. */
export const FedErrorCode = {
  /** connect protocol range does not overlap the peer's supported range. */
  VERSION_MISMATCH: 'version_mismatch',
  /** device token missing, unknown, revoked, or malformed. */
  UNAUTHENTICATED: 'unauthenticated',
  /** authenticated but the required capability was not granted at pairing. */
  FORBIDDEN_CAPS: 'forbidden_caps',
  /** request deadline elapsed before completion. */
  DEADLINE_EXCEEDED: 'deadline_exceeded',
  /** task cancelled by the initiator or an operator. */
  CANCELLED: 'cancelled',
  /** idempotencyKey replayed with a different payload fingerprint. */
  IDEMPOTENCY_CONFLICT: 'idempotency_conflict',
  /** receiver at queue capacity; retry after retryAfterMs. */
  BUSY_RETRY_AFTER: 'busy_retry_after',
  /** params failed wire-boundary validation. */
  PAYLOAD_INVALID: 'payload_invalid',
  /** method exists in the catalog but is not mounted on this peer. */
  METHOD_NOT_MOUNTED: 'method_not_mounted',
  /** method unknown to the peer. */
  METHOD_UNKNOWN: 'method_unknown',
  /** task referenced by id does not exist (or expired from the table). */
  TASK_NOT_FOUND: 'task_not_found',
  /** unexpected server-side failure; safe to retry with a new trace id. */
  INTERNAL: 'internal',
} as const

export type FedErrorCode = (typeof FedErrorCode)[keyof typeof FedErrorCode]

/** Wire error payload carried by a failed `res` frame. */
export interface FedError {
  code: FedErrorCode
  message: string
  /** Present only for BUSY_RETRY_AFTER: earliest safe retry time offset. */
  retryAfterMs?: number
  /** Server-side trace id when the failure happened mid-pipeline. */
  traceId?: string
}

export function fedError(code: FedErrorCode, message: string, extra?: Omit<FedError, 'code' | 'message'>): FedError {
  return { code, message, ...extra }
}

/** Narrow an unknown thrown value into a FedError for wire emission. */
export function toFedError(value: unknown, traceId?: string): FedError {
  if (isFedError(value)) return value
  const message = value instanceof Error ? value.message : String(value)
  return fedError(FedErrorCode.PAYLOAD_INVALID, message, traceId ? { traceId } : undefined)
}

export function isFedError(value: unknown): value is FedError {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return typeof record.code === 'string'
    && typeof record.message === 'string'
    && Object.values(FedErrorCode).includes(record.code as FedErrorCode)
}
