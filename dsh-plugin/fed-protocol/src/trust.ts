/**
 * Local trust table — the operator's decisions, persisted.
 *
 * There is deliberately no distributed version of this and none is wanted.
 * Trust is a LOCAL decision, so two peers may legitimately disagree about a
 * third; rejecting a peer is therefore instant and needs no propagation
 * (delete the row).
 *
 * The persistence adapter is treated as the shared medium, and every public
 * operation re-reads it first. That is not defensive coding for its own sake:
 * a hive node is two processes (the accepting half and the dialing half) that
 * share one state directory, so an approval made on one side must become
 * visible to the other without a network round trip or a restart. Re-reading a
 * few hundred bytes per trust decision costs nothing next to a handshake.
 *
 * Why the SAS comparison actually works, since the SAS derives from PUBLIC keys
 * and is not a secret:
 * - To impersonate A to B, an attacker must present A's public key. That passes
 *   the derive check, but signing B's nonce needs A's private key, which the
 *   attacker does not have → the signature fails.
 * - To produce a valid signature it must use its own key, and then B derives a
 *   different deviceId and a different SAS than the one A's screen shows. The
 *   two operators see mismatched digits and refuse.
 * So a relay in the middle has no path. The remaining failure mode is
 * procedural, not cryptographic: an operator who types the value shown on their
 * OWN screen confirms the attacker. Hence the wording on approve().
 */
import { isFedCapability, type FedCapability, type PeerIdentity, type TrustStore } from './auth.js'
import type { DeviceId, PublicKeyB64 } from './identity.js'

/** On-disk shape. Flat so the file stays hand-inspectable when debugging. */
export interface TrustedPeerRow {
  deviceId: DeviceId
  publicKey: PublicKeyB64
  displayName: string
  caps: readonly FedCapability[]
  trustedAtMs: number
}

/** A peer whose signature verified but whose SAS no operator has confirmed yet. */
export interface PendingTrust {
  deviceId: DeviceId
  publicKey: PublicKeyB64
  /** Computed locally. The operator must type the value shown on the OTHER screen. */
  sas: string
  nickname: string
  /** What the peer advertised; the operator may narrow it, never widen it silently. */
  advertisedCaps: readonly FedCapability[]
  requestedAtMs: number
  expiresAtMs: number
}

/**
 * Everything the table owns, in one document.
 *
 * Trusted rows and pending requests share a file on purpose: the operator CLI
 * is then a pure file reader/writer with no listener to connect to, and both
 * processes on the machine observe one another's decisions.
 */
export interface TrustSnapshot {
  trusted: readonly TrustedPeerRow[]
  pending: readonly PendingTrust[]
}

export interface TrustPersistence {
  load(): TrustSnapshot | undefined
  save(snapshot: TrustSnapshot): void
}

export type TrustApprovalOutcome =
  | { ok: true; peer: PeerIdentity }
  | { ok: false; reason: 'sas_mismatch' | 'no_pending_request' }

/**
 * How long an unconfirmed request survives. Bounded so an unauthenticated peer
 * cannot camp in the pending set: a port scan never grows the table past one
 * row per deviceId, and stale rows drain on their own.
 */
const DEFAULT_TRUST_WINDOW_MS = 10 * 60_000

/** Default grants when the operator does not narrow them explicitly. */
const DEFAULT_GRANTED_CAPS: readonly FedCapability[] = ['task.exec', 'task.ask', 'state.report']

export class TrustTable implements TrustStore {
  readonly #rows = new Map<DeviceId, TrustedPeerRow>()
  readonly #pending = new Map<DeviceId, PendingTrust>()
  readonly #persistence: TrustPersistence | undefined
  readonly #windowMs: number

  constructor(persistence?: TrustPersistence, windowMs = DEFAULT_TRUST_WINDOW_MS) {
    this.#persistence = persistence
    this.#windowMs = windowMs
    this.#refresh()
  }

  /**
   * Re-read the shared document. Called before every public operation so this
   * instance converges with the other process on the same machine.
   */
  #refresh(): void {
    const snapshot = this.#persistence?.load()
    if (snapshot === undefined) return
    this.#rows.clear()
    for (const row of snapshot.trusted ?? []) {
      // Drop rows that no longer typecheck rather than refusing to boot: one
      // corrupt entry must not cost the operator every other trusted peer.
      if (typeof row?.deviceId !== 'string' || typeof row?.publicKey !== 'string') continue
      this.#rows.set(row.deviceId, {
        deviceId: row.deviceId,
        publicKey: row.publicKey,
        displayName: typeof row.displayName === 'string' ? row.displayName : '',
        caps: (Array.isArray(row.caps) ? row.caps : []).filter(isFedCapability),
        trustedAtMs: typeof row.trustedAtMs === 'number' ? row.trustedAtMs : 0,
      })
    }
    this.#pending.clear()
    for (const request of snapshot.pending ?? []) {
      if (typeof request?.deviceId !== 'string' || typeof request?.sas !== 'string') continue
      this.#pending.set(request.deviceId, request)
    }
  }

  #save(): void {
    this.#persistence?.save({ trusted: [...this.#rows.values()], pending: [...this.#pending.values()] })
  }

  /** Drop expired requests. Returns true when something was removed. */
  #purgeExpired(now: number): boolean {
    let removed = false
    for (const [deviceId, request] of this.#pending) {
      if (request.expiresAtMs <= now) {
        this.#pending.delete(deviceId)
        removed = true
      }
    }
    return removed
  }

  /** TrustStore. A key that no longer matches the row means no trust. */
  lookup(deviceId: DeviceId, publicKey: PublicKeyB64): PeerIdentity | undefined {
    this.#refresh()
    const row = this.#rows.get(deviceId)
    if (row === undefined || row.publicKey !== publicKey) return undefined
    return { deviceId: row.deviceId, publicKey: row.publicKey, displayName: row.displayName, caps: row.caps, trustedAtMs: row.trustedAtMs }
  }

  isTrusted(deviceId: DeviceId): boolean {
    this.#refresh()
    return this.#rows.has(deviceId)
  }

  /**
   * Record a signature-verified peer awaiting confirmation. Idempotent per
   * deviceId: reconnecting refreshes the window instead of queueing a second
   * prompt, so a reconnect loop cannot spam the operator.
   */
  requestTrust(input: {
    deviceId: DeviceId
    publicKey: PublicKeyB64
    sas: string
    nickname: string
    advertisedCaps?: readonly FedCapability[]
  }): PendingTrust {
    this.#refresh()
    const now = Date.now()
    const purged = this.#purgeExpired(now)
    const pending: PendingTrust = {
      deviceId: input.deviceId,
      publicKey: input.publicKey,
      sas: input.sas,
      nickname: input.nickname,
      advertisedCaps: (input.advertisedCaps ?? []).filter(isFedCapability),
      requestedAtMs: this.#pending.get(input.deviceId)?.requestedAtMs ?? now,
      expiresAtMs: now + this.#windowMs,
    }
    this.#pending.set(input.deviceId, pending)
    this.#save()
    void purged
    return pending
  }

  pending(): readonly PendingTrust[] {
    this.#refresh()
    if (this.#purgeExpired(Date.now())) this.#save()
    return [...this.#pending.values()]
  }

  pendingFor(deviceId: DeviceId): PendingTrust | undefined {
    this.#refresh()
    if (this.#purgeExpired(Date.now())) this.#save()
    return this.#pending.get(deviceId)
  }

  /**
   * Operator confirmation.
   *
   * `sas` MUST be what the operator read off the OTHER machine's screen. Typing
   * the locally displayed value always succeeds and confirms whoever is on the
   * other end — exactly the attacker's goal. The comparison IS the mechanism,
   * not a formality.
   *
   * No constant-time compare: the SAS derives from public keys, so it is not a
   * secret and a timing oracle would leak nothing.
   */
  approve(deviceId: DeviceId, sas: string, options?: { nickname?: string; caps?: readonly FedCapability[] }): TrustApprovalOutcome {
    this.#refresh()
    if (this.#purgeExpired(Date.now())) this.#save()
    const pending = this.#pending.get(deviceId)
    if (pending === undefined) return { ok: false, reason: 'no_pending_request' }
    if (pending.sas !== sas) return { ok: false, reason: 'sas_mismatch' }
    const narrowed = (options?.caps ?? pending.advertisedCaps.filter((cap) => DEFAULT_GRANTED_CAPS.includes(cap))).filter(isFedCapability)
    const row: TrustedPeerRow = {
      deviceId,
      publicKey: pending.publicKey,
      displayName: options?.nickname ?? pending.nickname,
      caps: narrowed.length > 0 ? narrowed : DEFAULT_GRANTED_CAPS,
      trustedAtMs: Date.now(),
    }
    this.#rows.set(deviceId, row)
    this.#pending.delete(deviceId)
    this.#save()
    return { ok: true, peer: { ...row } }
  }

  /** Operator dismissal. Drops the request only; no lasting record either way. */
  deny(deviceId: DeviceId): boolean {
    this.#refresh()
    const removed = this.#pending.delete(deviceId)
    if (removed) this.#save()
    return removed
  }

  /** Instant local rejection — the peer's next handshake simply finds no row. */
  revoke(deviceId: DeviceId): boolean {
    this.#refresh()
    // Also clear any pending request: leaving one behind would silently
    // re-trust the peer the next time an operator pressed approve.
    const hadPending = this.#pending.delete(deviceId)
    const removed = this.#rows.delete(deviceId)
    if (removed || hadPending) this.#save()
    return removed
  }

  /** Re-label a trusted peer. Display only: never touches the id or the key. */
  relabel(deviceId: DeviceId, displayName: string): boolean {
    this.#refresh()
    const row = this.#rows.get(deviceId)
    if (row === undefined) return false
    if (row.displayName === displayName) return false
    row.displayName = displayName
    this.#save()
    return true
  }

  list(): readonly PeerIdentity[] {
    this.#refresh()
    return [...this.#rows.values()].map((row) => ({ ...row }))
  }
}
