/**
 * hive federation wire protocol — openclaw-style three-frame exchange.
 *
 * Frame shapes (A-class benchmark: openclaw gateway-protocol):
 *   req   { type:"req",   id, method, params, ...delivery }
 *   res   { type:"res",   id, ok, payload | error }
 *   event { type:"event", event, payload, seq }
 *
 * Every inbound frame passes assertFrame — the wire boundary is the one place
 * untrusted JSON is trusted to become a typed value (AGENTS.md: validate at
 * wire boundaries; trust TypeScript only inside same-process typed edges).
 */
import { FedErrorCode, fedError, isFedError, type FedError } from './errors.js'
import { FedCapability, type DeviceId, type PublicKeyB64 } from './auth.js'

/**
 * Wire protocol version. Bumped to 2 by the self-sovereign identity cut (D-020).
 * v1 peers are REJECTED rather than half-supported: there is no meaningful
 * translation between "an issuer told me who you are" and "you proved it
 * yourself" — a bridge would just be the center server again, in disguise.
 */
export const PROTOCOL_VERSION = 2
/** Oldest wire protocol this build accepts. */
export const MIN_PROTOCOL_VERSION = 2
/** Newest wire protocol this build accepts. */
export const MAX_PROTOCOL_VERSION = 2

/**
 * Connection roles. `host` is a federated peer runtime (it accepts directed
 * tasks); `user` is the LOCAL operator surface — the CLI/UI gated by the
 * loopback user token.
 *
 * There is deliberately no `gateway` role: every peer both dials and accepts, so
 * "who happened to accept this socket" carries no authority.
 */
export type PeerRole = 'host' | 'user'

/**
 * connect.req params — the first frame on any connection.
 *
 * Note what is NOT here: no credential. A connect frame only *claims* an
 * identity; the claim becomes meaningful after step 2 (authenticate) proves
 * possession of the private key. A signature is required even for an
 * already-trusted peer — otherwise copying a trusted peer's PUBLIC key would be
 * enough to impersonate it.
 */
export interface ConnectParams {
  role: PeerRole
  protocol: { readonly min: number; readonly max: number }
  /** Self-declared public key; the acceptor derives the id from it. */
  publicKey?: PublicKeyB64
  /**
   * The dialer's own fresh nonce. The acceptor signs it, which is what proves
   * the ACCEPTOR's identity to the dialer — without this, verification would be
   * one-way and an attacker could impersonate the acceptor.
   */
  clientNonce?: string
  /**
   * Operator-facing label for this peer, editable locally at any time. Cosmetic
   * by construction: display and dispatch-by-name only, never an identity source.
   */
  nickname?: string
  /** Present on role:"user": the LOCAL loopback token. Never a federation credential. */
  userToken?: string
  /** Capability advertisement; re-validated locally, never trusted from the wire. */
  caps?: readonly FedCapability[]
}

/** authenticate.req params — step 2: prove possession of the claimed key. */
export interface AuthenticateParams {
  /** Ed25519 over the acceptor's nonce, bound to both peer ids. */
  signature: string
}

/**
 * connect res payload (role:"host"). Always a challenge: a fresh nonce the peer
 * must sign, plus the SAS the two operators compare out of band.
 */
export interface ChallengeOk {
  protocol: number
  /** Fresh, per-connection, single-use. Never reused, never sent in two places. */
  nonce: string
  /** Six digits derived from BOTH public keys; an attacker swapping a key changes it. */
  sas: string
  /** The acceptor's own id, so the dialer can rebuild the canonical signed message. */
  acceptorId: DeviceId
  /** How the acceptor wants to be shown. The dialer cannot infer this from hello. */
  acceptorNickname: string
  /** The acceptor's public key — the dialer needs it to verify the proof below. */
  acceptorPublicKey: PublicKeyB64
  /** The acceptor's proof over the dialer's clientNonce. Makes authentication mutual. */
  signature: string
  /** Server wall clock so peers can bound drift for deadline math. */
  serverTimeMs: number
}

/** authenticate res payload on success. */
export interface HelloOk {
  protocol: number
  peer: { role: PeerRole; deviceId: DeviceId; nickname: string }
  /** Server wall clock so peers can bound drift for deadline math. */
  serverTimeMs: number
  /**
   * False when the signature verified but no operator has confirmed the SAS yet.
   * The connection is held open (the peer may only send trust negotiation), and
   * the local operator is prompted. Never treat trusted:false as authorized.
   */
  trusted: boolean
  /** Granted capabilities, from the LOCAL trust table — not from the peer's advertisement. */
  caps?: readonly FedCapability[]
}

/** Request frame. */
export interface FedRequest {
  readonly type: 'req'
  /** Correlation id; scopes the res frame. Never used for authorization. */
  readonly id: string
  readonly method: string
  readonly params: unknown
  /** Absolute epoch ms after which the receiver should abort and reply DEADLINE_EXCEEDED. */
  readonly deadlineMs?: number
  /** Required for side-effecting methods; replays with the same fingerprint resolve to the first result. */
  readonly idempotencyKey?: string
  /** Pipeline trace id; generated by the initiator when absent. */
  readonly traceId?: string
}

/** Response frame. */
export interface FedResponse {
  readonly type: 'res'
  readonly id: string
  readonly ok: boolean
  readonly payload?: unknown
  readonly error?: FedError
}

/** Event frame; `seq` is per-connection monotonic and drives ack-based backpressure. */
export interface FedEvent {
  readonly type: 'event'
  readonly event: string
  readonly payload: unknown
  readonly seq: number
}

export type FedFrame = FedRequest | FedResponse | FedEvent

/** Event backpressure acknowledgement frame (transport-level, same wire). */
export interface FedEventAck {
  readonly type: 'event.ack'
  /** Highest contiguous seq the receiver has durably processed. */
  readonly ackedThrough: number
  /** Receiver asks the sender to slow down (credit-style backpressure hint). */
  readonly window: number
}

export type FedWireFrame = FedFrame | FedEventAck

export function isRequest(frame: unknown): frame is FedRequest {
  return isFrameOf(frame, 'req') && typeof (frame as FedRequest).method === 'string'
    && 'params' in (frame as FedRequest)
}

export function isResponse(frame: unknown): frame is FedResponse {
  if (!isFrameOf(frame, 'res')) return false
  const f = frame as FedResponse
  if (typeof f.ok !== 'boolean') return false
  return f.ok ? 'payload' in f : isFedError(f.error)
}

export function isEvent(frame: unknown): frame is FedEvent {
  return isFrameOf(frame, 'event') && typeof (frame as FedEvent).event === 'string'
    && typeof (frame as FedEvent).seq === 'number'
}

export function isEventAck(frame: unknown): frame is FedEventAck {
  return isFrameOf(frame, 'event.ack') && typeof (frame as FedEventAck).ackedThrough === 'number'
}

function isFrameOf(frame: unknown, type: string): boolean {
  return typeof frame === 'object' && frame !== null && (frame as Record<string, unknown>).type === type
}

/** Parse and validate one untrusted wire frame. Throws FedError(PAYLOAD_INVALID). */
export function decodeFrame(raw: unknown): FedWireFrame {
  if (isRequest(raw)) {
    assertValidId(raw.id)
    assertValidMethod(raw.method)
    assertOptionalTiming(raw)
    return raw
  }
  if (isResponse(raw)) {
    assertValidId(raw.id)
    return raw
  }
  if (isEvent(raw)) {
    if (!Number.isInteger(raw.seq) || raw.seq < 0) {
      throw payloadInvalid('event.seq must be a non-negative integer')
    }
    return raw
  }
  if (isEventAck(raw)) {
    if (!Number.isInteger(raw.ackedThrough) || raw.ackedThrough < 0) {
      throw payloadInvalid('event.ack.ackedThrough must be a non-negative integer')
    }
    if (!Number.isInteger(raw.window) || raw.window < 0) {
      throw payloadInvalid('event.ack.window must be a non-negative integer')
    }
    return raw
  }
  throw payloadInvalid('frame.type must be one of req | res | event | event.ack')
}

/**
 * Validate a connect handshake and negotiate the protocol version.
 * Rejects with VERSION_MISMATCH when the ranges do not overlap.
 */
export function negotiateProtocol(params: ConnectParams): number {
  const { min, max } = params.protocol
  if (!Number.isInteger(min) || !Number.isInteger(max) || min > max) {
    throw payloadInvalid('connect.protocol must be an integer range min <= max')
  }
  const overlapMin = Math.max(min, MIN_PROTOCOL_VERSION)
  const overlapMax = Math.min(max, MAX_PROTOCOL_VERSION)
  if (overlapMin > overlapMax) {
    throw fedError(FedErrorCode.VERSION_MISMATCH,
      `peer supports ${min}..${max}, we support ${MIN_PROTOCOL_VERSION}..${MAX_PROTOCOL_VERSION}`)
  }
  return overlapMax
}

/** Capabilities are always re-validated server-side; client lists are advertisements only. */
export function sanitizeAdvertisedCaps(value: unknown): readonly FedCapability[] {
  if (!Array.isArray(value)) return []
  return value.filter((entry): entry is FedCapability =>
    typeof entry === 'string' && (Object.values(FedCapability) as string[]).includes(entry))
}

function assertValidId(id: string): void {
  if (typeof id !== 'string' || id.length === 0 || id.length > 128) {
    throw payloadInvalid('frame.id must be a non-empty string of at most 128 chars')
  }
}

function assertValidMethod(method: string): void {
  if (typeof method !== 'string' || method.length === 0 || method.length > 128) {
    throw payloadInvalid('req.method must be a non-empty string of at most 128 chars')
  }
}

function assertOptionalTiming(raw: FedRequest): void {
  if (raw.deadlineMs !== undefined && (!Number.isFinite(raw.deadlineMs) || raw.deadlineMs <= 0)) {
    throw payloadInvalid('req.deadlineMs must be a positive epoch-ms number when present')
  }
  if (raw.idempotencyKey !== undefined
    && (typeof raw.idempotencyKey !== 'string' || raw.idempotencyKey.length === 0 || raw.idempotencyKey.length > 128)) {
    throw payloadInvalid('req.idempotencyKey must be a non-empty string of at most 128 chars when present')
  }
  if (raw.traceId !== undefined
    && (typeof raw.traceId !== 'string' || raw.traceId.length === 0 || raw.traceId.length > 128)) {
    throw payloadInvalid('req.traceId must be a non-empty string of at most 128 chars when present')
  }
}

function payloadInvalid(message: string): FedError {
  return fedError(FedErrorCode.PAYLOAD_INVALID, message)
}
