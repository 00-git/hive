import { i as PeerIdentity, n as FedCapability, r as HostStateDigest, t as DeviceId } from "./index-BW9r-ZZU.js";
//#region src/registry.d.ts
interface HostConnectionState {
  identity: PeerIdentity;
  /** Live dispatch channel; undefined while the peer is mid-reconnect. */
  send: ((frame: unknown) => void) | undefined;
  lastSeenMs: number;
  digest: HostStateDigest | undefined;
}
declare class HostRegistry {
  #private;
  /** Attach or re-attach a live connection for an authorized peer. */
  bind(identity: PeerIdentity, send: (frame: unknown) => void): void;
  unbind(deviceId: DeviceId): void;
  touch(deviceId: DeviceId, digest: HostStateDigest): void;
  /** Rows for peers we have heard from; offline rows included, marked by `online`. */
  list(): readonly (HostStateDigest & {
    online: boolean;
  })[];
  /**
   * Resolve a dispatch target by device id, the peer's own nickname, or the
   * operator's label for it.
   *
   * Name matching is a convenience lookup ONLY: the request runs against the
   * deviceId resolved here, and capabilities are read from the identity that was
   * authorized at handshake time — never from the name somebody typed. That is
   * what stops a peer from granting itself rights by renaming to match a target.
   */
  findForDispatch(nameOrId: string): HostConnectionState | undefined;
  /** Capabilities come from the authorized identity, never from the wire. */
  hasCap(deviceId: DeviceId, cap: FedCapability): boolean;
  isOnline(deviceId: DeviceId): boolean;
}
//#endregion
export { HostConnectionState, HostRegistry };
//# sourceMappingURL=registry.d.ts.map