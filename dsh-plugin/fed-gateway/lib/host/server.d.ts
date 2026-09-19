import { r as HostStateDigest, t as DeviceId } from "./index-BW9r-ZZU.js";
//#region src/server.d.ts
interface GatewayConfig {
  port?: number;
  /** Empty/absent = auto-detect the VPN interface, and refuse to listen if absent. */
  bindHost?: string;
  auditPath?: string;
  stateDir?: string;
  /** Label this node advertises to peers. Display only. */
  nickname?: string;
}
declare class GatewayServer {
  #private;
  constructor(config?: GatewayConfig);
  get identity(): {
    deviceId: DeviceId;
    nickname: string;
  };
  get userToken(): string;
  get listening(): boolean;
  /** Operator-visible peers awaiting SAS confirmation. */
  pendingTrust(): readonly {
    deviceId: string;
    nickname: string;
    sas: string;
  }[];
  /**
   * Live peer rows for the operator surface. Read-only and derived: it exposes
   * what the registry already knows, never a trust decision.
   */
  peerStates(): readonly (HostStateDigest & {
    online: boolean;
  })[];
  /**
   * Start the listener.
   *
   * Fail-closed: with no explicit bindHost and no detectable VPN interface we do
   * NOT fall back to the LAN or to 0.0.0.0. Staying closed is the safe failure
   * (visible, and fixable by starting the VPN); silently widening exposure is
   * neither.
   */
  start(): void;
  stop(): void;
}
//#endregion
export { GatewayConfig, GatewayServer };
//# sourceMappingURL=server.d.ts.map