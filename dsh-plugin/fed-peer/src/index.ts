/**
 * hive-fed-peer — the shared layer every hive node runs.
 *
 * A hive node is symmetric: it both listens for inbound peers and dials
 * outbound ones, so "who accepted this socket" carries no authority and there
 * is no center server to be down. This package holds the parts both halves must
 * agree on — the handshake state machines and the on-disk state — so they
 * cannot drift into two subtly different protocol implementations.
 *
 * Not a dsh bundle: it is compiled into the two plugin packages, so a machine
 * installs `hive-fed-gateway` (the accepting half) and `hive-fed-host` (the
 * dialing half) and gets a full node.
 *
 * Build order matters: fed-protocol → fed-peer → fed-gateway / fed-host.
 */
export {
  acceptorOnAuthenticate,
  acceptorOnConnect,
  acceptorOnTrustApproved,
  dialerBuildConnect,
  dialerOnChallenge,
  dialerOnHello,
  newAcceptorState,
  newDialerState,
} from './handshake.js'
export type { AcceptorOutcome, AcceptorState, DialerOutcome, DialerState, HandshakeDeps } from './handshake.js'
export { PeerTable, keepConnection, loadOrCreateIdentity, trustPersistenceFor } from './stores.js'
export type { KnownPeer, LoadedIdentity } from './stores.js'
export { detectVpnAddress, resolveListenTarget } from './network.js'
export type { DetectedAddress, ListenTarget } from './network.js'
// Re-export the whole protocol surface: consumers import one path, which also
// guarantees they all use a single copy of the shared types and tables.
export * from '../../fed-protocol/lib/host/index.js'
