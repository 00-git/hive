import { AuditLog } from "./audit.js";
//#region src/ops.d.ts
interface OpsConfig {
  whitelistDirs: readonly string[];
  audit: AuditLog;
  maxReadBytes?: number;
}
interface OpResult {
  ok: boolean;
  op: string;
  result?: unknown;
  denied?: string;
}
/** Parse the task prompt as a structured op. MVP contract, documented in README. */
declare function parsePrompt(prompt: string): {
  op: string;
  args: Record<string, unknown>;
};
declare function runOp(config: OpsConfig, traceId: string, op: string, args: Record<string, unknown>): Promise<OpResult>;
//#endregion
export { OpResult, OpsConfig, parsePrompt, runOp };
//# sourceMappingURL=ops.d.ts.map