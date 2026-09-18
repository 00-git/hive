import { randomInt } from "node:crypto";
//#region src/pairing.ts
/**
* Pairing sessions: 6-digit codes, 5-minute TTL, 3 wrong approvals lock the
* operator session for 60s (C ?????????user ?????.
*/
const CODE_TTL_MS = 3e5;
const MAX_WRONG_ATTEMPTS = 3;
const LOCKOUT_MS = 6e4;
var PairingManager = class {
	#pending = /* @__PURE__ */ new Map();
	#wrongAttempts = /* @__PURE__ */ new Map();
	/** Create a pending pairing for an unauthenticated host connection. */
	create(deviceName, caps) {
		const now = Date.now();
		for (const [code, pending] of this.#pending) if (pending.expiresAtMs <= now) this.#pending.delete(code);
		let code = "";
		do
			code = String(randomInt(0, 1e6)).padStart(6, "0");
		while (this.#pending.has(code));
		const pending = {
			code,
			deviceName,
			caps,
			createdAtMs: now,
			expiresAtMs: now + CODE_TTL_MS
		};
		this.#pending.set(code, pending);
		return pending;
	}
	/** Operator approves a code. Returns undefined + reason when rejected. */
	approve(code, operatorKey) {
		const now = Date.now();
		const attempts = this.#wrongAttempts.get(operatorKey);
		if (attempts !== void 0 && attempts.lockedUntil > now) return {
			ok: false,
			reason: "approval attempts locked",
			lockedForMs: attempts.lockedUntil - now
		};
		const pending = this.#pending.get(code);
		if (pending === void 0 || pending.expiresAtMs <= now) {
			this.#recordWrong(operatorKey, now);
			return {
				ok: false,
				reason: "unknown or expired pairing code"
			};
		}
		this.#pending.delete(code);
		this.#wrongAttempts.delete(operatorKey);
		return {
			ok: true,
			pending
		};
	}
	#recordWrong(operatorKey, now) {
		const attempts = this.#wrongAttempts.get(operatorKey) ?? {
			count: 0,
			lockedUntil: 0
		};
		attempts.count += 1;
		if (attempts.count >= MAX_WRONG_ATTEMPTS) {
			attempts.lockedUntil = now + LOCKOUT_MS;
			attempts.count = 0;
		}
		this.#wrongAttempts.set(operatorKey, attempts);
	}
	get pendingCount() {
		return this.#pending.size;
	}
};
//#endregion
export { PairingManager };

//# sourceMappingURL=pairing.js.map