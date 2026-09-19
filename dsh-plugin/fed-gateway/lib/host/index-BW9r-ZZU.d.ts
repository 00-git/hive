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
/** Raw Ed25519 public key, base64url of the 32-byte JWK `x` coordinate. */
type PublicKeyB64 = string;
//#endregion
//#region src/auth.d.ts
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
/**
 * An operator-approved peer. Only ever created by the SAS confirmation flow —
 * never by anything that arrived over the wire.
 */
interface PeerIdentity {
  deviceId: DeviceId;
  /** Pinned at confirmation. A different key is a different deviceId, by construction. */
  publicKey: PublicKeyB64;
  /** Operator-facing label. Cosmetic only — never an identity source. */
  displayName: string;
  caps: readonly FedCapability[];
  /** When the operator confirmed the SAS (audit + ordering, not a decision input). */
  trustedAtMs: number;
}
/**
 * Host state digest — the anti-信息差 payload injected into the main agent's context.
 *
 * Written by the peer about ITSELF (single writer per row), so no conflict
 * resolution is needed: a stale copy is simply overwritten by the next report.
 * `nickname` is the owning peer's own label and carries no authority — every
 * receiver keys off deviceId, so a peer cannot promote itself by renaming.
 */
interface HostStateDigest {
  deviceId: DeviceId;
  /** Operator-facing label, freely editable by the owning peer. Never an identity source. */
  nickname: string;
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
export { PeerIdentity as i, FedCapability as n, HostStateDigest as r, DeviceId as t };
//# sourceMappingURL=index-BW9r-ZZU.d.ts.map