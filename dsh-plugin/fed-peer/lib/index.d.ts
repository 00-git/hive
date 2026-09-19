import { AuthenticateParams, ChallengeOk, ConnectParams, DeviceId, FedCapability, FedError, HelloOk, PeerIdentityMaterial, PublicKeyB64, TrustPersistence, TrustTable } from "../../fed-protocol/lib/host/index.js";
export * from "../../fed-protocol/lib/host/index.js";
//#region src/handshake.d.ts
/** Everything both halves need. Injected so tests can drive them without I/O. */
interface HandshakeDeps {
  readonly identity: PeerIdentityMaterial;
  readonly trust: TrustTable;
  /**
   * How THIS node wants to be displayed. Sent to the dialer in the challenge,
   * because the dialer has no other way to learn it — `hello.peer` describes
   * the dialer, not the acceptor, and mixing those up labels every peer with
   * its own name.
   */
  readonly selfNickname?: string;
}
/**
 * Acceptor-side state. `stage` is the single source of truth for what the next
 * inbound frame is allowed to be — a peer cannot skip a step by sending the
 * frame it would eventually be allowed to send.
 */
interface AcceptorState {
  stage: 'awaiting-connect' | 'awaiting-authenticate' | 'trust-pending' | 'authenticated';
  /** Set once the dialer's key is known; the id is always DERIVED, never taken from the wire. */
  dialerId?: DeviceId;
  dialerPublicKey?: PublicKeyB64;
  dialerNickname?: string;
  /** Single-use. Regenerated per connection, never reused across attempts. */
  serverNonce?: string;
  /** Locally computed. The operator must type the value from the OTHER screen. */
  sas?: string;
  advertisedCaps?: readonly FedCapability[];
}
type AcceptorOutcome = {
  readonly ok: true;
  readonly step: 'challenge';
  readonly challenge: ChallengeOk;
} | {
  readonly ok: true;
  readonly step: 'authenticated';
  readonly hello: HelloOk;
} | {
  readonly ok: false;
  readonly error: FedError;
};
declare function newAcceptorState(): AcceptorState;
/**
 * Step 1 — the dialer's connect frame.
 *
 * Note the ordering: everything derivable is derived BEFORE any trust question
 * is asked, so an attacker cannot learn whether a given id is trusted without
 * first proving it holds that id's key.
 */
declare function acceptorOnConnect(deps: HandshakeDeps, state: AcceptorState, params: ConnectParams | undefined): {
  state: AcceptorState;
  outcome: AcceptorOutcome;
};
/**
 * Step 2 — the dialer's signature over our nonce.
 *
 * A failed signature is a hard reject, but a verified signature from an
 * unconfirmed peer is NOT: the connection stays open in `trust-pending` so an
 * operator can compare six digits. Conflating those two would either lock out
 * every new machine or let unverified peers through.
 */
declare function acceptorOnAuthenticate(deps: HandshakeDeps, state: AcceptorState, params: AuthenticateParams | undefined): {
  state: AcceptorState;
  outcome: AcceptorOutcome;
};
/** The operator confirmed the SAS for a held peer; promote the connection. */
declare function acceptorOnTrustApproved(deps: HandshakeDeps, state: AcceptorState): {
  state: AcceptorState;
  outcome: AcceptorOutcome;
};
/**
 * Dialer-side state. The dialer keeps `clientNonce` until the challenge arrives
 * because it is what the acceptor must sign — discarding it early would make
 * the acceptor's proof unverifiable.
 */
interface DialerState {
  stage: 'idle' | 'awaiting-challenge' | 'awaiting-hello' | 'ready';
  clientNonce?: string;
  acceptorId?: DeviceId;
  acceptorPublicKey?: PublicKeyB64;
  /** How the ACCEPTOR wants to be shown; only the challenge carries this. */
  acceptorNickname?: string;
  /** Locally computed; compared against what the challenge claims. */
  sas?: string;
}
type DialerOutcome = {
  readonly ok: true;
  readonly step: 'authenticate';
  readonly params: AuthenticateParams;
} | {
  readonly ok: true;
  readonly step: 'ready';
  /** OUR decision: an operator on this machine confirmed the acceptor. */
  readonly trusted: boolean;
  /** THEIR decision, reported in hello. Kept separate — see dialerOnHello. */
  readonly peerTrustsUs: boolean;
  readonly nickname: string;
} | {
  readonly ok: false;
  readonly error: FedError;
};
declare function newDialerState(): DialerState;
/** Build the connect frame. Always the first thing a dialer sends. */
declare function dialerBuildConnect(deps: HandshakeDeps, state: DialerState, options?: {
  nickname?: string;
  caps?: readonly FedCapability[];
}): {
  state: DialerState;
  params: ConnectParams;
};
/**
 * Verify the acceptor's challenge.
 *
 * Three independent checks, all fatal: the id must derive from the presented
 * key, the proof must verify over OUR nonce, and the claimed SAS must equal the
 * one we compute locally. The last one is what a person then re-checks out of
 * band — if the acceptor is an impostor, its key differs and so does the SAS.
 */
declare function dialerOnChallenge(deps: HandshakeDeps, state: DialerState, challenge: ChallengeOk | undefined): {
  state: DialerState;
  outcome: DialerOutcome;
};
/**
 * Fold the acceptor's hello in, and decide for OURSELVES whether the acceptor is
 * trusted. `hello.trusted` describes the acceptor's opinion of us and must never
 * be reused as our opinion of them — that inversion is the classic mutual-auth
 * bug, and it is why the dialer consults its own table here.
 */
declare function dialerOnHello(deps: HandshakeDeps, state: DialerState, hello: HelloOk | undefined): {
  state: DialerState;
  outcome: DialerOutcome;
};
//#endregion
//#region src/stores.d.ts
interface LoadedIdentity {
  identity: PeerIdentityMaterial;
  /** True the first time this machine ever ran — worth telling the operator once. */
  created: boolean;
}
/**
 * Load this machine's identity, minting one on first run.
 *
 * The private key never leaves this file, so identity is not something another
 * peer can grant, revoke, or transfer — the whole point of dropping tokens.
 */
declare function loadOrCreateIdentity(stateDir: string): LoadedIdentity;
/**
 * Trust-table persistence. Callers pass the same dir as the identity.
 *
 * One document holds both the trusted rows and the pending requests, which is
 * what lets the operator CLI be a pure file editor (no listener to connect to)
 * and lets the two processes on a machine see each other's decisions.
 */
declare function trustPersistenceFor(stateDir: string): TrustPersistence;
/**
 * One remembered address for a peer.
 *
 * Addresses are hints, never identity: the same peer may be reachable at
 * several (LAN address, OpenP2P local forward port), and a stale entry costs
 * one failed dial, not a security decision.
 */
interface KnownPeer {
  deviceId: DeviceId;
  publicKey: PublicKeyB64;
  nickname: string;
  /** Where WE reach it. Already a local forward address when tunneled. */
  address: string;
  /** Whether the local operator has confirmed it. Untrusted rows are dial candidates only. */
  trusted: boolean;
  lastSeenMs: number;
}
/**
 * Address book for the mesh. Deliberately separate from the trust table: this
 * one is a cache that gossip may append to freely, while trust is only ever
 * written by an operator.
 */
declare class PeerTable {
  #private;
  constructor(stateDir?: string);
  upsert(peer: Omit<KnownPeer, 'lastSeenMs'> & {
    lastSeenMs?: number;
  }): KnownPeer;
  get(deviceId: DeviceId): KnownPeer | undefined;
  remove(deviceId: DeviceId): boolean;
  list(): readonly KnownPeer[];
  /** Dial candidates: everyone we know an address for, except ourselves. */
  dialCandidates(selfId: DeviceId): readonly KnownPeer[];
}
/**
 * Decide which of two connections to the same peer to keep.
 *
 * Both sides dial, and duplicates are resolved by a rule both ends can compute
 * from ids they already have, so they always reach the same verdict: the socket
 * initiated by the lexicographically smaller deviceId wins.
 *
 * Why both sides dial rather than "the smaller id dials": either end may be the
 * only one that knows an address (addresses are learned by gossip, and behind
 * OpenP2P each side configures its own forward). Under a strict one-dialer rule
 * the peer that never learned the address could never connect, and the pair
 * would deadlock waiting for each other.
 *
 * @param remoteInitiated true when the remote end opened this socket
 * @returns true when THIS socket should be kept
 */
declare function keepConnection(localId: DeviceId, remoteId: DeviceId, remoteInitiated: boolean): boolean;
//#endregion
//#region src/network.d.ts
interface DetectedAddress {
  address: string;
  iface: string;
}
/** First non-internal IPv4 on an interface that looks like a tunnel, if any. */
declare function detectVpnAddress(): DetectedAddress | undefined;
type ListenTarget =
/** Bound to a discovered tunnel address. */
{
  mode: 'vpn';
  address: string;
  iface: string;
} |
/** An explicit operator setting; taken as-is, including 0.0.0.0. */
{
  mode: 'explicit';
  address: string;
} |
/** Nothing to bind — stay closed. */
{
  mode: 'refused';
  reason: string;
};
/**
 * Resolve the bind address. An explicit setting always wins, because the
 * operator may be deliberately exposing a different interface; absence of a
 * setting is what triggers detection, and a failed detection is what refuses.
 */
declare function resolveListenTarget(configured: string | undefined): ListenTarget;
//#endregion
export { type AcceptorOutcome, type AcceptorState, type DetectedAddress, type DialerOutcome, type DialerState, type HandshakeDeps, type KnownPeer, type ListenTarget, type LoadedIdentity, PeerTable, acceptorOnAuthenticate, acceptorOnConnect, acceptorOnTrustApproved, detectVpnAddress, dialerBuildConnect, dialerOnChallenge, dialerOnHello, keepConnection, loadOrCreateIdentity, newAcceptorState, newDialerState, resolveListenTarget, trustPersistenceFor };
//# sourceMappingURL=index.d.ts.map