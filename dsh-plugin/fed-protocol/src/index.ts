/**
 * hive-fed-protocol — host-half dsh plugin.
 *
 * Provides the `fedProtocol` service: the shared wire vocabulary (frames,
 * methods, errors) plus the authentication choke point used by both
 * hive-fed-gateway and hive-fed-host. Pure logic, zero I/O — transports live
 * in the gateway/host packages so this contract stays swappable (平台化约束:
 * 一切皆插件、可替换、可关闭).
 *
 * Model-visible ⟺ logged: nothing here reaches a model request; it only moves
 * bytes and validates boundaries.
 */
import type { DeviceTokenStore } from './auth.js'
import {
  MAX_PROTOCOL_VERSION,
  MIN_PROTOCOL_VERSION,
  PROTOCOL_VERSION,
  decodeFrame,
  negotiateProtocol,
  sanitizeAdvertisedCaps,
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
  type TaskState,
} from './methods.js'
import {
  FedCapability,
  asDeviceToken,
  authenticate,
  hashToken,
  issueDeviceToken,
  tokenHashesEqual,
  type DeviceId,
  type DeviceIdentity,
  type DeviceToken,
  type IssuedToken,
} from './auth.js'

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
  /** Single authentication choke point (禁止清单 enforcement). */
  authenticate(
    store: DeviceTokenStore,
    presented: unknown,
    context: { readonly source: string; readonly declaredName?: unknown },
  ): { identity: DeviceIdentity } | { error: 'unauthenticated' }
  issueDeviceToken(deviceId: DeviceId): IssuedToken
  hashToken(token: DeviceToken): string
  tokenHashesEqual(a: string, b: string): boolean
  asDeviceToken(value: unknown): DeviceToken | undefined
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
    authenticate,
    issueDeviceToken,
    hashToken,
    tokenHashesEqual,
    asDeviceToken,
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
  asDeviceToken,
  authenticate,
  hashToken,
  issueDeviceToken,
  tokenHashesEqual,
  fedError,
  toFedError,
}
export type {
  AgentAskParams,
  AgentTaskParams,
  ConnectParams,
  DeviceId,
  DeviceIdentity,
  DeviceToken,
  DeviceTokenStore,
  FedError,
  FedEvent,
  FedEventAck,
  FedFrame,
  FedRequest,
  FedResponse,
  FedWireFrame,
  FedCapability as FedCapabilityType,
  HelloOk,
  HostStateDigest,
  IssuedToken,
  PeerRole,
  TaskState,
}
