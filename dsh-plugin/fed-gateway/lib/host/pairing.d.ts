import { t as DeviceId } from "./index-CJtvQaJJ.js";
//#region src/pairing.d.ts
interface PendingPairing {
  code: string;
  deviceName: string;
  caps: readonly string[];
  createdAtMs: number;
  expiresAtMs: number;
}
interface ApprovedPairing {
  deviceId: DeviceId;
  token: string;
  deviceName: string;
}
declare class PairingManager {
  #private;
  /** Create a pending pairing for an unauthenticated host connection. */
  create(deviceName: string, caps: readonly string[]): PendingPairing;
  /** Operator approves a code. Returns undefined + reason when rejected. */
  approve(code: string, operatorKey: string): {
    ok: true;
    pending: PendingPairing;
  } | {
    ok: false;
    reason: string;
    lockedForMs?: number;
  };
  get pendingCount(): number;
}
//#endregion
export { ApprovedPairing, PairingManager, PendingPairing };
//# sourceMappingURL=pairing.d.ts.map