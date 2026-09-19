/**
 * Federation authorization — the single choke point.
 *
 * 硬约束 (安全模型第 6 条「禁止清单」, mirrored in the protocol tests): the ONLY
 * inputs consulted are (a) a handshake signature the transport has already
 * verified against the presented public key, and (b) membership in the local,
 * operator-approved trust table. Every other parameter — claimed device names,
 * capability lists, source address, headers — is audit metadata and cannot
 * influence the decision.
 *
 * Identity is self-sovereign (see identity.ts): there is no issuer, and
 * therefore no revocation list anyone must synchronize. An operator grants
 * trust once by comparing the SAS out of band; the table pins the peer after
 * that. Rejecting a peer is local by construction — delete its row.
 */
import { timingSafeEqual } from 'node:crypto'
import { deriveDeviceId, type DeviceId, type PublicKeyB64 } from './identity.js'

export type { DeviceId, PublicKeyB64 } from './identity.js'

/** Capability names a host may grant at pairing. Closed set (security invariant). */
export const FedCapability = {
  /** host accepts agent.task dispatch and runs it under local approval. */
  TASK_EXEC: 'task.exec',
  /** host answers agent.ask introspection questions. */
  TASK_ASK: 'task.ask',
  /** host streams state summaries (host.state). */
  STATE_REPORT: 'state.report',
  /** host may receive signed plugin install requests (host-side confirm still required). */
  PLUGIN_INSTALL: 'plugin.install',
} as const

export type FedCapability = (typeof FedCapability)[keyof typeof FedCapability]

export function isFedCapability(value: string): value is FedCapability {
  return (Object.values(FedCapability) as string[]).includes(value)
}

/**
 * An operator-approved peer. Only ever created by the SAS confirmation flow —
 * never by anything that arrived over the wire.
 */
export interface PeerIdentity {
  deviceId: DeviceId
  /** Pinned at confirmation. A different key is a different deviceId, by construction. */
  publicKey: PublicKeyB64
  /** Operator-facing label. Cosmetic only — never an identity source. */
  displayName: string
  caps: readonly FedCapability[]
  /** When the operator confirmed the SAS (audit + ordering, not a decision input). */
  trustedAtMs: number
}

/** Local trust table contract (implementation persists to trusted-peers.json). */
export interface TrustStore {
  /**
   * Returns the peer only when an operator approved it AND the stored key still
   * matches the presented one. Returning undefined is how a peer is rejected;
   * there is no separate revocation mechanism to keep in sync.
   */
  lookup(deviceId: DeviceId, publicKey: PublicKeyB64): PeerIdentity | undefined
}

/**
 * The two facts the transport establishes before authorization. They are kept
 * separate because they fail differently and the caller must react differently:
 * a broken signature is a hard reject, while an unverified peer just needs an
 * operator to compare six digits.
 */
export interface HandshakeProof {
  readonly deviceId: DeviceId
  readonly publicKey: PublicKeyB64
  /** Output of verifyHandshake(); computed by the transport, consumed here. */
  readonly signatureVerified: boolean
}

export type AuthorizationFailure =
  /** Key/id binding or signature failed — the peer is not who it claims. */
  | 'unauthenticated'
  /** Signature is fine but no operator has confirmed this peer yet. */
  | 'untrusted'

/**
 * Authorize an inbound peer request.
 *
 * The ONLY inputs consulted are the signature result and the local trust table;
 * every other parameter is diagnostic metadata for the audit log and cannot
 * influence the decision. This is the single choke point for the 禁止清单 rule.
 */
export function authorize(
  store: TrustStore,
  proof: HandshakeProof,
  context: { readonly source: string; readonly declaredName?: unknown },
): { identity: PeerIdentity } | { error: AuthorizationFailure } {
  // Self-certification first: the id must derive from the key that signed. A
  // claimed id is worthless unless it is provably the claimant's own.
  if (deriveDeviceId(proof.publicKey) !== proof.deviceId) return { error: 'unauthenticated' }
  if (!proof.signatureVerified) return { error: 'unauthenticated' }
  const identity = store.lookup(proof.deviceId, proof.publicKey)
  if (identity === undefined) return { error: 'untrusted' }
  // context is intentionally unused for the decision; reference it so linters
  // keep the parameter as part of the audited call shape.
  void context.source
  void context.declaredName
  return { identity }
}

/**
 * Constant-time comparison for the LOCAL user surface token.
 *
 * Scope note: this token never crosses a trust boundary — it only gates the
 * loopback CLI against the local listener, so it is not part of the federation
 * identity model and needs no registry.
 */
export function localTokenMatches(presented: unknown, expected: string): boolean {
  if (typeof presented !== 'string') return false
  const a = Buffer.from(presented, 'utf8')
  const b = Buffer.from(expected, 'utf8')
  return a.length === b.length && timingSafeEqual(a, b)
}
