/**
 * Shared handshake state machines — acceptor and dialer halves.
 *
 * Both halves live here because they must agree byte-for-byte on what gets
 * signed; keeping them in separate packages is how two implementations drift
 * apart and start rejecting each other for no visible reason. They are written
 * as pure functions over an explicit state object rather than classes with
 * hidden fields, so every transition is directly testable.
 *
 * Shape of the exchange (two round trips, mutual authentication):
 *
 *   dialer                                    acceptor
 *     |-- connect {publicKey, clientNonce} ----->|  derive id, mint serverNonce,
 *     |                                          |  sign clientNonce
 *     |<-- challenge {nonce, sas, proof} --------|
 *     |  verify proof (acceptor is who it says)  |
 *     |  compare sas against the local one       |
 *     |-- authenticate {signature} ------------->|  verify over serverNonce
 *     |                                          |  trust? -> hello.trusted
 *     |<-- hello {trusted} -----------------------|
 *
 * Neither side can fabricate the other's proof without a fresh nonce from the
 * other, which is what makes this mutual rather than one-way.
 */
import {
  FedErrorCode,
  MAX_PROTOCOL_VERSION,
  MIN_PROTOCOL_VERSION,
  PROTOCOL_VERSION,
  fedError,
  type AuthenticateParams,
  type ChallengeOk,
  type ConnectParams,
  type DeviceId,
  type FedCapability,
  type FedError,
  type HelloOk,
  type PeerIdentityMaterial,
  type PublicKeyB64,
  type TrustTable,
  computeSas,
  createNonce,
  deriveDeviceId,
  isFedCapability,
  signHandshake,
  verifyHandshake,
} from '../../fed-protocol/lib/host/index.js'

/** Everything both halves need. Injected so tests can drive them without I/O. */
export interface HandshakeDeps {
  readonly identity: PeerIdentityMaterial
  readonly trust: TrustTable
  /**
   * How THIS node wants to be displayed. Sent to the dialer in the challenge,
   * because the dialer has no other way to learn it — `hello.peer` describes
   * the dialer, not the acceptor, and mixing those up labels every peer with
   * its own name.
   */
  readonly selfNickname?: string
}

/**
 * Acceptor-side state. `stage` is the single source of truth for what the next
 * inbound frame is allowed to be — a peer cannot skip a step by sending the
 * frame it would eventually be allowed to send.
 */
export interface AcceptorState {
  stage: 'awaiting-connect' | 'awaiting-authenticate' | 'trust-pending' | 'authenticated'
  /** Set once the dialer's key is known; the id is always DERIVED, never taken from the wire. */
  dialerId?: DeviceId
  dialerPublicKey?: PublicKeyB64
  dialerNickname?: string
  /** Single-use. Regenerated per connection, never reused across attempts. */
  serverNonce?: string
  /** Locally computed. The operator must type the value from the OTHER screen. */
  sas?: string
  advertisedCaps?: readonly FedCapability[]
}

export type AcceptorOutcome =
  | { readonly ok: true; readonly step: 'challenge'; readonly challenge: ChallengeOk }
  | { readonly ok: true; readonly step: 'authenticated'; readonly hello: HelloOk }
  | { readonly ok: false; readonly error: FedError }

export function newAcceptorState(): AcceptorState {
  return { stage: 'awaiting-connect' }
}

/** Sanitize an operator-facing label. Cosmetic only — never an identity input. */
function cleanNickname(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback
  // Strip control characters: the label is rendered and logged downstream.
  const trimmed = value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 64)
  return trimmed.length > 0 ? trimmed : fallback
}

/**
 * Step 1 — the dialer's connect frame.
 *
 * Note the ordering: everything derivable is derived BEFORE any trust question
 * is asked, so an attacker cannot learn whether a given id is trusted without
 * first proving it holds that id's key.
 */
export function acceptorOnConnect(
  deps: HandshakeDeps,
  state: AcceptorState,
  params: ConnectParams | undefined,
): { state: AcceptorState; outcome: AcceptorOutcome } {
  if (state.stage !== 'awaiting-connect') {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.PAYLOAD_INVALID, 'connect already received on this connection') } }
  }
  // Every entry point tolerates an absent/partial params object: these run
  // inside the message loop, where a thrown TypeError would take the whole dsh
  // process down with it (handler failures must never escape).
  const publicKey = params?.publicKey
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'connect requires a public key') } }
  }
  const clientNonce = params?.clientNonce
  if (typeof clientNonce !== 'string' || clientNonce.length < 16) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.PAYLOAD_INVALID, 'connect requires a client nonce') } }
  }

  let dialerId: DeviceId
  try {
    dialerId = deriveDeviceId(publicKey)
  } catch {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'malformed public key') } }
  }

  const serverNonce = createNonce()
  const sas = computeSas(deps.identity.publicKey, publicKey)
  // The acceptor proves itself over the DIALER's nonce. Without this step the
  // dialer would authenticate the acceptor on nothing but a self-declared key.
  const proof = signHandshake(deps.identity.privateKeyPem, clientNonce, dialerId, deps.identity.deviceId)

  const next: AcceptorState = {
    stage: 'awaiting-authenticate',
    dialerId,
    dialerPublicKey: publicKey,
    dialerNickname: cleanNickname(params?.nickname, dialerId),
    serverNonce,
    sas,
    advertisedCaps: Array.isArray(params?.caps) ? params.caps.filter(isFedCapability) : [],
  }
  return {
    state: next,
    outcome: {
      ok: true,
      step: 'challenge',
      challenge: {
        protocol: PROTOCOL_VERSION,
        nonce: serverNonce,
        sas,
        acceptorId: deps.identity.deviceId,
        acceptorNickname: cleanNickname(deps.selfNickname, String(deps.identity.deviceId)),
        acceptorPublicKey: deps.identity.publicKey,
        signature: proof,
        serverTimeMs: Date.now(),
      } satisfies ChallengeOk,
    },
  }
}

/**
 * Step 2 — the dialer's signature over our nonce.
 *
 * A failed signature is a hard reject, but a verified signature from an
 * unconfirmed peer is NOT: the connection stays open in `trust-pending` so an
 * operator can compare six digits. Conflating those two would either lock out
 * every new machine or let unverified peers through.
 */
export function acceptorOnAuthenticate(
  deps: HandshakeDeps,
  state: AcceptorState,
  params: AuthenticateParams | undefined,
): { state: AcceptorState; outcome: AcceptorOutcome } {
  if (state.stage !== 'awaiting-authenticate') {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'authenticate requires a preceding connect') } }
  }
  const { dialerId, dialerPublicKey, serverNonce, sas } = state
  if (dialerId === undefined || dialerPublicKey === undefined || serverNonce === undefined || sas === undefined) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.INTERNAL, 'handshake state incomplete') } }
  }
  const signature = params?.signature
  if (typeof signature !== 'string' || signature.length === 0) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'signature required') } }
  }
  const verified = verifyHandshake(dialerPublicKey, serverNonce, dialerId, deps.identity.deviceId, signature)
  if (!verified) {
    // Drop the nonce: a failed proof must not be retryable against the same one.
    return { state: { ...state, stage: 'awaiting-connect', serverNonce: undefined }, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'signature verification failed') } }
  }

  const trusted = deps.trust.lookup(dialerId, dialerPublicKey)
  if (trusted !== undefined) {
    const next: AcceptorState = { ...state, stage: 'authenticated' }
    return { state: next, outcome: { ok: true, step: 'authenticated', hello: helloFor(deps, next, true) } }
  }

  // Signature is good, identity is proven, but nobody has vouched for it yet.
  deps.trust.requestTrust({
    deviceId: dialerId,
    publicKey: dialerPublicKey,
    sas,
    nickname: state.dialerNickname ?? dialerId,
    advertisedCaps: state.advertisedCaps,
  })
  const next: AcceptorState = { ...state, stage: 'trust-pending' }
  return { state: next, outcome: { ok: true, step: 'authenticated', hello: helloFor(deps, next, false) } }
}

/** The operator confirmed the SAS for a held peer; promote the connection. */
export function acceptorOnTrustApproved(deps: HandshakeDeps, state: AcceptorState): { state: AcceptorState; outcome: AcceptorOutcome } {
  if (state.stage !== 'trust-pending') {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.FORBIDDEN_CAPS, 'no trust decision is pending for this connection') } }
  }
  const next: AcceptorState = { ...state, stage: 'authenticated' }
  return { state: next, outcome: { ok: true, step: 'authenticated', hello: helloFor(deps, next, true) } }
}

function helloFor(deps: HandshakeDeps, state: AcceptorState, trusted: boolean): HelloOk {
  const deviceId = state.dialerId ?? deps.identity.deviceId
  const granted = trusted && state.dialerPublicKey !== undefined
    ? deps.trust.lookup(deviceId, state.dialerPublicKey)
    : undefined
  return {
    protocol: PROTOCOL_VERSION,
    peer: { role: 'host', deviceId, nickname: state.dialerNickname ?? deviceId },
    serverTimeMs: Date.now(),
    trusted,
    caps: granted?.caps,
  }
}

/**
 * Dialer-side state. The dialer keeps `clientNonce` until the challenge arrives
 * because it is what the acceptor must sign — discarding it early would make
 * the acceptor's proof unverifiable.
 */
export interface DialerState {
  stage: 'idle' | 'awaiting-challenge' | 'awaiting-hello' | 'ready'
  clientNonce?: string
  acceptorId?: DeviceId
  acceptorPublicKey?: PublicKeyB64
  /** How the ACCEPTOR wants to be shown; only the challenge carries this. */
  acceptorNickname?: string
  /** Locally computed; compared against what the challenge claims. */
  sas?: string
}

export type DialerOutcome =
  | { readonly ok: true; readonly step: 'authenticate'; readonly params: AuthenticateParams }
  | {
      readonly ok: true
      readonly step: 'ready'
      /** OUR decision: an operator on this machine confirmed the acceptor. */
      readonly trusted: boolean
      /** THEIR decision, reported in hello. Kept separate — see dialerOnHello. */
      readonly peerTrustsUs: boolean
      readonly nickname: string
    }
  | { readonly ok: false; readonly error: FedError }

export function newDialerState(): DialerState {
  return { stage: 'idle' }
}

/** Build the connect frame. Always the first thing a dialer sends. */
export function dialerBuildConnect(
  deps: HandshakeDeps,
  state: DialerState,
  options?: { nickname?: string; caps?: readonly FedCapability[] },
): { state: DialerState; params: ConnectParams } {
  const clientNonce = createNonce()
  return {
    state: { ...state, stage: 'awaiting-challenge', clientNonce },
    params: {
      role: 'host',
      protocol: { min: MIN_PROTOCOL_VERSION, max: MAX_PROTOCOL_VERSION },
      publicKey: deps.identity.publicKey,
      clientNonce,
      nickname: options?.nickname ?? '',
      caps: options?.caps ?? [],
    },
  }
}

/**
 * Verify the acceptor's challenge.
 *
 * Three independent checks, all fatal: the id must derive from the presented
 * key, the proof must verify over OUR nonce, and the claimed SAS must equal the
 * one we compute locally. The last one is what a person then re-checks out of
 * band — if the acceptor is an impostor, its key differs and so does the SAS.
 */
export function dialerOnChallenge(
  deps: HandshakeDeps,
  state: DialerState,
  challenge: ChallengeOk | undefined,
): { state: DialerState; outcome: DialerOutcome } {
  if (state.stage !== 'awaiting-challenge' || state.clientNonce === undefined) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'challenge without a preceding connect') } }
  }
  if (challenge === undefined) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.PAYLOAD_INVALID, 'challenge payload missing') } }
  }
  let derived: DeviceId
  try {
    derived = deriveDeviceId(challenge.acceptorPublicKey)
  } catch {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'acceptor sent a malformed key') } }
  }
  if (derived !== challenge.acceptorId) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'acceptor id does not match its key') } }
  }
  if (!verifyHandshake(challenge.acceptorPublicKey, state.clientNonce, deps.identity.deviceId, derived, challenge.signature)) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'acceptor proof did not verify') } }
  }
  const sas = computeSas(deps.identity.publicKey, challenge.acceptorPublicKey)
  if (sas !== challenge.sas) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'sas mismatch: the two ends disagree on the keys in play') } }
  }

  const next: DialerState = { ...state, stage: 'awaiting-hello', acceptorId: derived, acceptorPublicKey: challenge.acceptorPublicKey, acceptorNickname: cleanNickname(challenge.acceptorNickname, String(derived)), sas }
  const signature = signHandshake(deps.identity.privateKeyPem, challenge.nonce, deps.identity.deviceId, derived)
  return {
    state: next,
    outcome: { ok: true, step: 'authenticate', params: { signature } },
  }
}

/**
 * Fold the acceptor's hello in, and decide for OURSELVES whether the acceptor is
 * trusted. `hello.trusted` describes the acceptor's opinion of us and must never
 * be reused as our opinion of them — that inversion is the classic mutual-auth
 * bug, and it is why the dialer consults its own table here.
 */
export function dialerOnHello(
  deps: HandshakeDeps,
  state: DialerState,
  hello: HelloOk | undefined,
): { state: DialerState; outcome: DialerOutcome } {
  if (state.stage !== 'awaiting-hello' || state.acceptorId === undefined || state.acceptorPublicKey === undefined || state.sas === undefined) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'hello without a preceding challenge') } }
  }
  if (hello?.peer === undefined || typeof hello.peer.deviceId !== 'string') {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.PAYLOAD_INVALID, 'hello payload missing a peer') } }
  }
  // hello.peer describes US, as seen by the acceptor — so it must echo our own
  // id. Comparing it against the acceptor's id is the easy mistake here: it
  // would never match, and the failure looks like a protocol bug rather than a
  // confused field.
  if (hello.peer.deviceId !== deps.identity.deviceId) {
    return { state, outcome: { ok: false, error: fedError(FedErrorCode.UNAUTHENTICATED, 'hello describes an unexpected peer') } }
  }
  const mine = deps.trust.lookup(state.acceptorId, state.acceptorPublicKey)
  if (mine === undefined) {
    // Held, exactly like the acceptor's side: the operator must confirm.
    // The label is the ACCEPTOR's own nickname from the challenge — NOT
    // hello.peer.nickname, which is the acceptor's name for US.
    deps.trust.requestTrust({
      deviceId: state.acceptorId,
      publicKey: state.acceptorPublicKey,
      sas: state.sas,
      nickname: state.acceptorNickname ?? String(state.acceptorId),
      advertisedCaps: hello.caps,
    })
  } else {
    deps.trust.relabel(state.acceptorId, state.acceptorNickname ?? String(state.acceptorId))
  }
  const next: DialerState = { ...state, stage: 'ready' }
  // Both flags are returned separately rather than pre-ANDed: the caller has to
  // keep watching them, because either side's operator may confirm later and a
  // link only becomes usable once BOTH have.
  return { state: next, outcome: { ok: true, step: 'ready', trusted: mine !== undefined, peerTrustsUs: hello.trusted === true, nickname: state.acceptorNickname ?? String(state.acceptorId) } }
}
