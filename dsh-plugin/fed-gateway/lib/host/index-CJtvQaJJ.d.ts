//#region ../fed-protocol/lib/host/index.d.ts
//#region src/auth.d.ts
/** Opaque device token issued at pairing. Branded: never a bare string. */
declare const deviceTokenBrand: unique symbol;
type DeviceToken = string & {
  readonly [deviceTokenBrand]: true;
};
/** Stable device identity minted by the gateway at pairing approval. */
declare const deviceIdBrand: unique symbol;
type DeviceId = string & {
  readonly [deviceIdBrand]: true;
};
/** Capability names a host may grant at pairing. Closed set (security invariant). */
declare const FedCapability: {
  /** host accepts agent.task dispatch and runs it under local approval. */
  readonly TASK_EXEC: "task.exec";
  /** host answers agent.ask introspection questions. */
  readonly TASK_ASK: "task.ask";
  /** host streams state summaries (host.state). */
  readonly STATE_REPORT: "state.report";
  /** host may receive signed plugin install requests (host-side confirm still required). */
  readonly PLUGIN_INSTALL: "plugin.install";
};
type FedCapability = (typeof FedCapability)[keyof typeof FedCapability];
/** Identity resolved server-side from the token store — never from client claims. */
interface DeviceIdentity {
  deviceId: DeviceId;
  displayName: string;
  caps: readonly FedCapability[];
  pairedAt: number;
}
/** Minimal token store contract the gateway (issuer side) implements. */
interface DeviceTokenStore {
  /** Resolve identity by raw token. Returns undefined for unknown/revoked tokens. */
  resolve(token: DeviceToken): DeviceIdentity | undefined;
}
/** Host state digest — the anti-信息差 payload injected into the main agent's context. */
interface HostStateDigest {
  deviceId: string;
  displayName: string;
  os: string;
  lanAddress: string;
  cpuLoadPct?: number;
  memTotalMb?: number;
  memFreeMb?: number;
  diskSummaries?: readonly {
    readonly mount: string;
    readonly freeMb: number;
  }[];
  reportedAtMs: number;
}
//#endregion
export { FedCapability as a, DeviceTokenStore as i, DeviceIdentity as n, HostStateDigest as o, DeviceToken as r, DeviceId as t };
//# sourceMappingURL=index-CJtvQaJJ.d.ts.map