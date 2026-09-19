/**
 * hive-fed-protocol — host-half dsh plugin.
 *
 * Provides the `fedProtocol` service: the shared wire vocabulary (frames,
 * methods, errors), the self-sovereign identity primitives (identity.ts) and the
 * single authorization choke point (auth.ts) used by both hive-fed-gateway and
 * hive-fed-host. Pure logic, zero I/O — transports live in the peer packages so
 * this contract stays swappable (平台化约束: 一切皆插件、可替换、可关闭).
 *
 * Model-visible ⟺ logged: nothing here reaches a model request; it only moves
 * bytes and validates boundaries.
 */
import {
  MAX_PROTOCOL_VERSION,
  MIN_PROTOCOL_VERSION,
  PROTOCOL_VERSION,
  decodeFrame,
  negotiateProtocol,
  sanitizeAdvertisedCaps,
  type AuthenticateParams,
  type ChallengeOk,
  type ConnectParams,
  type FedEvent,
  type FedEventAck,
  type FedFrame,
  type FedRequest,
  type FedResponse,
  type FedWireFrame,
  type HelloOk,
  type PeerRole,
} from './frames.js'
import { FedErrorCode, fedError, toFedError, type FedError } from './errors.js'
import {
  FedEvent as FedEventName,
  FedMethod,
  IDEMPOTENT_METHODS,
  requiresIdempotencyKey,
  type AgentAskParams,
  type AgentTaskParams,
  type HostStateDigest,
  type PeerAnnouncement,
  type TaskState,
  type TrustApproveParams,
} from './methods.js'
import {
  FedCapability,
  authorize,
  isFedCapability,
  localTokenMatches,
  type AuthorizationFailure,
  type HandshakeProof,
  type PeerIdentity,
  type TrustStore,
} from './auth.js'
import {
  computeSas,
  createNonce,
  deriveDeviceId,
  formatDeviceId,
  generateIdentity,
  restoreIdentity,
  signHandshake,
  verifyHandshake,
  type DeviceId,
  type PeerIdentityMaterial,
  type PrivateKeyPem,
  type PublicKeyB64,
} from './identity.js'
import {
  TrustTable,
  type PendingTrust,
  type TrustApprovalOutcome,
  type TrustedPeerRow,
  type TrustPersistence,
  type TrustSnapshot,
} from './trust.js'

export const name = 'hive-fed-protocol'

/** Deployment-tunable config. Protocol/security constants are NOT here (AGENTS.md). */
export interface Config {
  /** Reject connects whose negotiated version is not exactly this major line. Default true. */
  strictVersionCheck?: boolean
}

function assertConfig(config: Config | undefined): Required<Config> {
  const resolved: Required<Config> = { strictVersionCheck: config?.strictVersionCheck ?? true }
  if (typeof resolved.strictVersionCheck !== 'boolean') {
    throw new Error('hive-fed-protocol: config.strictVersionCheck must be a boolean when present')
  }
  return resolved
}

/** The service exposed on `ctx` under the key `fedProtocol`. */
export interface FedProtocolService {
  readonly version: { readonly current: number; readonly min: number; readonly max: number }
  readonly methods: typeof FedMethod
  readonly events: typeof FedEventName
  readonly errorCodes: typeof FedErrorCode
  /** Parse + validate one untrusted wire frame. Throws FedError(PAYLOAD_INVALID). */
  decodeFrame(raw: unknown): FedWireFrame
  negotiateProtocol(params: ConnectParams): number
  sanitizeAdvertisedCaps(value: unknown): readonly FedCapability[]
  requiresIdempotencyKey(method: string): boolean
  /** Single authorization choke point (禁止清单 enforcement). */
  authorize(
    store: TrustStore,
    proof: HandshakeProof,
    context: { readonly source: string; readonly declaredName?: unknown },
  ): { identity: PeerIdentity } | { error: AuthorizationFailure }
  /** Self-sovereign identity primitives — no issuer, no registry to consult. */
  readonly identity: {
    generate(): PeerIdentityMaterial
    restore(publicKey: PublicKeyB64, privateKeyPem: PrivateKeyPem, createdAtMs?: number): PeerIdentityMaterial
    deriveDeviceId(publicKey: PublicKeyB64): DeviceId
    createNonce(): string
    signHandshake(privateKeyPem: PrivateKeyPem, nonce: string, selfId: DeviceId, peerId: DeviceId): string
    verifyHandshake(publicKey: PublicKeyB64, nonce: string, dialerId: DeviceId, acceptorId: DeviceId, signature: string): boolean
    computeSas(publicKeyA: PublicKeyB64, publicKeyB: PublicKeyB64): string
    formatDeviceId(deviceId: DeviceId): string
  }
  /** Loopback-only operator token check; NOT part of the federation identity model. */
  localTokenMatches(presented: unknown, expected: string): boolean
  isFedCapability(value: string): value is FedCapability
  fedError: typeof fedError
  toFedError: typeof toFedError
}

export function apply(ctx: unknown, config?: Config): void {
  const resolved = assertConfig(config)
  const service: FedProtocolService = {
    version: { current: PROTOCOL_VERSION, min: MIN_PROTOCOL_VERSION, max: MAX_PROTOCOL_VERSION },
    methods: FedMethod,
    events: FedEventName,
    errorCodes: FedErrorCode,
    decodeFrame,
    negotiateProtocol,
    sanitizeAdvertisedCaps,
    requiresIdempotencyKey,
    authorize,
    identity: {
      generate: generateIdentity,
      restore: restoreIdentity,
      deriveDeviceId,
      createNonce,
      signHandshake,
      verifyHandshake,
      computeSas,
      formatDeviceId,
    },
    localTokenMatches,
    isFedCapability,
    fedError,
    toFedError,
  }
  // cordis contexts expose provide(key, value) for service registration.
  // Fail loud (AGENTS.md) rather than silently degrading to a property write.
  const candidate = ctx as { provide?: (key: string, value: unknown) => void }
  if (typeof candidate.provide !== 'function') {
    throw new Error('hive-fed-protocol: host context does not expose provide(); not a cordis context')
  }
  candidate.provide('fedProtocol', service)
  // Referenced so the config contract stays part of the audited apply() shape
  // even while no option consumes it yet.
  void resolved
}

// Re-exports for gateway/host packages (single import surface: hive-fed-protocol).
export {
  MAX_PROTOCOL_VERSION,
  MIN_PROTOCOL_VERSION,
  PROTOCOL_VERSION,
  decodeFrame,
  negotiateProtocol,
  sanitizeAdvertisedCaps,
  FedErrorCode,
  FedCapability,
  FedMethod,
  FedEventName as FedEventCatalog,
  IDEMPOTENT_METHODS,
  requiresIdempotencyKey,
  authorize,
  isFedCapability,
  localTokenMatches,
  fedError,
  toFedError,
  computeSas,
  createNonce,
  deriveDeviceId,
  formatDeviceId,
  generateIdentity,
  restoreIdentity,
  signHandshake,
  verifyHandshake,
  TrustTable,
}
export type {
  AgentAskParams,
  AgentTaskParams,
  AuthenticateParams,
  AuthorizationFailure,
  ChallengeOk,
  ConnectParams,
  DeviceId,
  FedError,
  FedEvent,
  FedEventAck,
  FedFrame,
  FedRequest,
  FedResponse,
  FedWireFrame,
  FedCapability as FedCapabilityType,
  HandshakeProof,
  HelloOk,
  HostStateDigest,
  PeerAnnouncement,
  PeerIdentity,
  PeerIdentityMaterial,
  PeerRole,
  PendingTrust,
  PrivateKeyPem,
  PublicKeyB64,
  TaskState,
  TrustApprovalOutcome,
  TrustedPeerRow,
  TrustPersistence,
  TrustSnapshot,
  TrustApproveParams,
  TrustStore,
}
