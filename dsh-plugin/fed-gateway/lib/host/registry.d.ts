import { a as FedCapability, i as DeviceTokenStore, n as DeviceIdentity, o as HostStateDigest, r as DeviceToken, t as DeviceId } from "./index-CJtvQaJJ.js";
//#region src/registry.d.ts
interface HostConnectionState {
  identity: DeviceIdentity;
  /** Live dispatch channel; undefined while the host is mid-reconnect. */
  send: ((frame: unknown) => void) | undefined;
  lastSeenMs: number;
  digest: HostStateDigest | undefined;
}
declare class HostRegistry implements DeviceTokenStore {
  #private;
  /**
   * Persist the registry (token HASHES + identities — never raw tokens) so a
   * gateway restart does not force re-pairing (D-013).
   */
  setPersistence(file: string | undefined): void;
  mintDeviceId(): DeviceId;
  /** Register a freshly approved device: hash-only token storage (D-004). */
  registerToken(deviceId: DeviceId, rawToken: string, identity: DeviceIdentity): void;
  /** Revoke: token stops resolving immediately; the host must re-pair. */
  revoke(deviceId: DeviceId): boolean;
  /** DeviceTokenStore.resolve ??the ONLY identity source (?????? choke point). */
  resolve(token: DeviceToken): DeviceIdentity | undefined;
  /** Attach or re-attach a live connection for an authenticated host. */
  bind(identity: DeviceIdentity, send: (frame: unknown) => void): void;
  unbind(deviceId: DeviceId): void;
  touch(deviceId: DeviceId, digest: HostStateDigest): void;
  list(): readonly HostStateDigest[];
  /** Resolve a host by deviceId or displayName for dispatch. */
  findForDispatch(nameOrId: string): HostConnectionState | undefined;
  hasCap(deviceId: DeviceId, cap: FedCapability): boolean;
}
//#endregion
export { HostConnectionState, HostRegistry };
//# sourceMappingURL=registry.d.ts.map