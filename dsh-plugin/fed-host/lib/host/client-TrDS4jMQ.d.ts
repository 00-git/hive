//#region ../fed-protocol/lib/host/index.d.ts
//#endregion
//#region src/identity.d.ts
/**
 * Stable peer identity, self-derived from a public key. Branded so a bare
 * string can never be passed where an identity is required (dsh 跨边界 id
 * 品牌化约定). Defined here rather than in auth.ts because auth.ts consumes
 * identities and this module must stay import-free at runtime.
 */
declare const deviceIdBrand: unique symbol;
type DeviceId = string & {
  readonly [deviceIdBrand]: true;
};
//#endregion
//#region src/client.d.ts
interface HostConfig {
  /** Peers to dial, as ws:// URLs. Comma-separated in the settings card. */
  peerUrls?: readonly string[];
  /** Label other machines display for this one. Display only. */
  nickname?: string;
  /** Directory for identity, trust table, audit (defaults to ~/.hive). */
  stateDir?: string;
  /** Directories fs.read may touch. Defaults to [process.cwd()]. */
  whitelistDirs?: readonly string[];
  stateIntervalMs?: number;
}
declare class HostClient {
  #private;
  constructor(config?: HostConfig);
  /** This node's own id — the value every peer will key its trust row off. */
  get deviceId(): DeviceId;
  /** Peers awaiting THIS machine's operator confirmation (the outbound half). */
  pendingTrust(): readonly {
    deviceId: string;
    nickname: string;
    sas: string;
  }[];
  start(): void;
  stop(): void;
}
//#endregion
export { HostConfig as n, HostClient as t };
//# sourceMappingURL=client-TrDS4jMQ.d.ts.map