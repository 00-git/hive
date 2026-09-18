/**
 * Federation identity and authentication.
 *
 * Hard constraints (hive 安全模型第 6 条「禁止清单」, mirrored in the protocol tests):
 * - Identity is resolved ONLY by looking up a device token issued at pairing.
 *   Nothing supplied by the client — headers, claimed device names, capability
 *   lists — may contribute to an identity decision.
 * - A request from loopback, from an already-paired transport, or carrying any
 *   particular header is never sufficient on its own: explicit token + local
 *   approval + audit remain mandatory at every trust boundary.
 *
 * Tokens are opaque, branded, compared in constant time, and stored hashed.
 */
import { timingSafeEqual, createHash, randomBytes } from 'node:crypto'

/** Opaque device token issued at pairing. Branded: never a bare string. */
declare const deviceTokenBrand: unique symbol
export type DeviceToken = string & { readonly [deviceTokenBrand]: true }

/** Stable device identity minted by the gateway at pairing approval. */
declare const deviceIdBrand: unique symbol
export type DeviceId = string & { readonly [deviceIdBrand]: true }

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

/** Token issuance result: the raw token is shown/stored once by the receiver. */
export interface IssuedToken {
  token: DeviceToken
  tokenId: string
  tokenHash: string
}

/**
 * Mint a new device token. Returns the raw token exactly once; only the
 * SHA-256 hash is retained by the issuer (gateway compromise must not leak
 * reusable credentials — D-004 爆炸半径约束).
 */
export function issueDeviceToken(deviceId: DeviceId): IssuedToken {
  const raw = randomBytes(32).toString('base64url')
  const token = raw as DeviceToken
  return { token, tokenId: tokenIdFor(deviceId, token), tokenHash: hashToken(token) }
}

export function hashToken(token: DeviceToken): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

function tokenIdFor(deviceId: DeviceId, token: DeviceToken): string {
  return createHash('sha256').update(`${deviceId}:${token}`, 'utf8').digest('hex').slice(0, 16)
}

/** Constant-time token comparison over hashes (never over raw secrets). */
export function tokenHashesEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'hex')
  const bb = Buffer.from(b, 'hex')
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}

/** Narrow an untrusted string into a DeviceToken (format check only — lookup is separate). */
export function asDeviceToken(value: unknown): DeviceToken | undefined {
  if (typeof value !== 'string' || value.length < 32 || value.length > 128) return undefined
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined
  return value as DeviceToken
}

/** Identity resolved server-side from the token store — never from client claims. */
export interface DeviceIdentity {
  deviceId: DeviceId
  displayName: string
  caps: readonly FedCapability[]
  pairedAt: number
}

/** Minimal token store contract the gateway (issuer side) implements. */
export interface DeviceTokenStore {
  /** Resolve identity by raw token. Returns undefined for unknown/revoked tokens. */
  resolve(token: DeviceToken): DeviceIdentity | undefined
}

/**
 * Authenticate an inbound request.
 *
 * The ONLY input consulted is the presented token; every other parameter is
 * diagnostic metadata for the audit log and cannot influence the decision.
 * This is the single choke point for the 禁止清单 rule on the gateway side.
 */
export function authenticate(
  store: DeviceTokenStore,
  presented: unknown,
  context: { readonly source: string; readonly declaredName?: unknown },
): { identity: DeviceIdentity } | { error: 'unauthenticated' } {
  const token = asDeviceToken(presented)
  if (token === undefined) return { error: 'unauthenticated' }
  const identity = store.resolve(token)
  if (identity === undefined) return { error: 'unauthenticated' }
  // context is intentionally unused for the decision; reference it so linters
  // keep the parameter as part of the audited call shape.
  void context.source
  void context.declaredName
  return { identity }
}
