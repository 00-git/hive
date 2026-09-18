import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
//#region ../fed-protocol/lib/host/index.js
/**
* Structured federation error codes and error payloads.
*
* Error semantics are A-class benchmarked against dsh tool-call error structure:
* a stable code discriminant plus human-readable detail, machine-usable fields
* (retryAfterMs) kept separate from prose. Codes are security invariants —
* fixed set, never configurable (AGENTS.md: protocol constants stay fixed).
*/
/** Stable wire error codes. Closed set: add only with a protocol version bump. */
const FedErrorCode = {
	/** connect protocol range does not overlap the peer's supported range. */
	VERSION_MISMATCH: "version_mismatch",
	/** device token missing, unknown, revoked, or malformed. */
	UNAUTHENTICATED: "unauthenticated",
	/** authenticated but the required capability was not granted at pairing. */
	FORBIDDEN_CAPS: "forbidden_caps",
	/** request deadline elapsed before completion. */
	DEADLINE_EXCEEDED: "deadline_exceeded",
	/** task cancelled by the initiator or an operator. */
	CANCELLED: "cancelled",
	/** idempotencyKey replayed with a different payload fingerprint. */
	IDEMPOTENCY_CONFLICT: "idempotency_conflict",
	/** receiver at queue capacity; retry after retryAfterMs. */
	BUSY_RETRY_AFTER: "busy_retry_after",
	/** params failed wire-boundary validation. */
	PAYLOAD_INVALID: "payload_invalid",
	/** method exists in the catalog but is not mounted on this peer. */
	METHOD_NOT_MOUNTED: "method_not_mounted",
	/** method unknown to the peer. */
	METHOD_UNKNOWN: "method_unknown",
	/** task referenced by id does not exist (or expired from the table). */
	TASK_NOT_FOUND: "task_not_found",
	/** unexpected server-side failure; safe to retry with a new trace id. */
	INTERNAL: "internal"
};
function fedError(code, message, extra) {
	return {
		code,
		message,
		...extra
	};
}
/** Narrow an unknown thrown value into a FedError for wire emission. */
function toFedError(value, traceId) {
	if (isFedError(value)) return value;
	const message = value instanceof Error ? value.message : String(value);
	return fedError(FedErrorCode.PAYLOAD_INVALID, message, traceId ? { traceId } : void 0);
}
function isFedError(value) {
	if (typeof value !== "object" || value === null) return false;
	const record = value;
	return typeof record.code === "string" && typeof record.message === "string" && Object.values(FedErrorCode).includes(record.code);
}
/**
* Federation identity and authentication.
*
* Hard constraints (hive 安全模型第 6 条「禁止清单」, mirrored in the protocol tests):
* - Identity is resolved ONLY by looking up a device token issued at pairing.
*   Nothing supplied by the client — headers, claimed device names, capability
*   lists — may contribute to an identity decision.
* - A request from loopback, from an already-paired transport, or carrying any
*   particular header is never sufficient on its own: explicit token + local
*   approval + audit remain mandatory at every trust boundary.
*
* Tokens are opaque, branded, compared in constant time, and stored hashed.
*/
/** Capability names a host may grant at pairing. Closed set (security invariant). */
const FedCapability = {
	/** host accepts agent.task dispatch and runs it under local approval. */
	TASK_EXEC: "task.exec",
	/** host answers agent.ask introspection questions. */
	TASK_ASK: "task.ask",
	/** host streams state summaries (host.state). */
	STATE_REPORT: "state.report",
	/** host may receive signed plugin install requests (host-side confirm still required). */
	PLUGIN_INSTALL: "plugin.install"
};
/**
* Mint a new device token. Returns the raw token exactly once; only the
* SHA-256 hash is retained by the issuer (gateway compromise must not leak
* reusable credentials — D-004 爆炸半径约束).
*/
function issueDeviceToken(deviceId) {
	const token = randomBytes(32).toString("base64url");
	return {
		token,
		tokenId: tokenIdFor(deviceId, token),
		tokenHash: hashToken(token)
	};
}
function hashToken(token) {
	return createHash("sha256").update(token, "utf8").digest("hex");
}
function tokenIdFor(deviceId, token) {
	return createHash("sha256").update(`${deviceId}:${token}`, "utf8").digest("hex").slice(0, 16);
}
/** Constant-time token comparison over hashes (never over raw secrets). */
function tokenHashesEqual(a, b) {
	const ab = Buffer.from(a, "hex");
	const bb = Buffer.from(b, "hex");
	return ab.length === bb.length && timingSafeEqual(ab, bb);
}
/** Narrow an untrusted string into a DeviceToken (format check only — lookup is separate). */
function asDeviceToken(value) {
	if (typeof value !== "string" || value.length < 32 || value.length > 128) return void 0;
	if (!/^[A-Za-z0-9_-]+$/.test(value)) return void 0;
	return value;
}
function isRequest(frame) {
	return isFrameOf(frame, "req") && typeof frame.method === "string" && "params" in frame;
}
function isResponse(frame) {
	if (!isFrameOf(frame, "res")) return false;
	const f = frame;
	if (typeof f.ok !== "boolean") return false;
	return f.ok ? "payload" in f : isFedError(f.error);
}
function isEvent(frame) {
	return isFrameOf(frame, "event") && typeof frame.event === "string" && typeof frame.seq === "number";
}
function isEventAck(frame) {
	return isFrameOf(frame, "event.ack") && typeof frame.ackedThrough === "number";
}
function isFrameOf(frame, type) {
	return typeof frame === "object" && frame !== null && frame.type === type;
}
/** Parse and validate one untrusted wire frame. Throws FedError(PAYLOAD_INVALID). */
function decodeFrame(raw) {
	if (isRequest(raw)) {
		assertValidId(raw.id);
		assertValidMethod(raw.method);
		assertOptionalTiming(raw);
		return raw;
	}
	if (isResponse(raw)) {
		assertValidId(raw.id);
		return raw;
	}
	if (isEvent(raw)) {
		if (!Number.isInteger(raw.seq) || raw.seq < 0) throw payloadInvalid("event.seq must be a non-negative integer");
		return raw;
	}
	if (isEventAck(raw)) {
		if (!Number.isInteger(raw.ackedThrough) || raw.ackedThrough < 0) throw payloadInvalid("event.ack.ackedThrough must be a non-negative integer");
		if (!Number.isInteger(raw.window) || raw.window < 0) throw payloadInvalid("event.ack.window must be a non-negative integer");
		return raw;
	}
	throw payloadInvalid("frame.type must be one of req | res | event | event.ack");
}
/**
* Validate a connect handshake and negotiate the protocol version.
* Rejects with VERSION_MISMATCH when the ranges do not overlap.
*/
function negotiateProtocol(params) {
	const { min, max } = params.protocol;
	if (!Number.isInteger(min) || !Number.isInteger(max) || min > max) throw payloadInvalid("connect.protocol must be an integer range min <= max");
	const overlapMin = Math.max(min, 1);
	const overlapMax = Math.min(max, 1);
	if (overlapMin > overlapMax) throw fedError(FedErrorCode.VERSION_MISMATCH, `peer supports ${min}..${max}, we support 1..1`);
	return overlapMax;
}
function assertValidId(id) {
	if (typeof id !== "string" || id.length === 0 || id.length > 128) throw payloadInvalid("frame.id must be a non-empty string of at most 128 chars");
}
function assertValidMethod(method) {
	if (typeof method !== "string" || method.length === 0 || method.length > 128) throw payloadInvalid("req.method must be a non-empty string of at most 128 chars");
}
function assertOptionalTiming(raw) {
	if (raw.deadlineMs !== void 0 && (!Number.isFinite(raw.deadlineMs) || raw.deadlineMs <= 0)) throw payloadInvalid("req.deadlineMs must be a positive epoch-ms number when present");
	if (raw.idempotencyKey !== void 0 && (typeof raw.idempotencyKey !== "string" || raw.idempotencyKey.length === 0 || raw.idempotencyKey.length > 128)) throw payloadInvalid("req.idempotencyKey must be a non-empty string of at most 128 chars when present");
	if (raw.traceId !== void 0 && (typeof raw.traceId !== "string" || raw.traceId.length === 0 || raw.traceId.length > 128)) throw payloadInvalid("req.traceId must be a non-empty string of at most 128 chars when present");
}
function payloadInvalid(message) {
	return fedError(FedErrorCode.PAYLOAD_INVALID, message);
}
/**
* Federation method and event catalogs.
*
* Naming is A-class benchmarked against dsh ctx.* service method conventions:
* domain-prefixed, verb-last where a noun reads better, closed sets.
* Side-effecting methods REQUIRE an idempotencyKey on the request frame.
*/
const FedMethod = {
	/** any peer → gateway: first frame on a connection (role + protocol range + token). */
	CONNECT: "connect",
	/** host → gateway: present a pairing code, request a device token. */
	PAIR_REQUEST: "pair.request",
	/** user surface → gateway: approve a pending pairing code. */
	PAIR_APPROVE: "pair.approve",
	/** gateway → user surfaces: a pairing code awaits approval. */
	PAIR_PENDING_EVENT: "pair.pending",
	/** host → gateway: advertise caps and current state summary (post-connect). */
	HOST_REGISTER: "host.register",
	/** host → gateway: periodic state digest push (also available as an event). */
	HOST_STATE_REPORT: "host.state.report",
	/** gateway → host: dispatch one directed task. Side-effecting. */
	AGENT_TASK: "agent.task",
	/** gateway → host / host → gateway: cancel an in-flight task. Side-effecting. */
	AGENT_TASK_CANCEL: "agent.task.cancel",
	/** gateway → host: ask a bounded introspection question (no side effects). */
	AGENT_ASK: "agent.ask",
	/** user surface → gateway: send a chat turn. Side-effecting. */
	CHAT_SEND: "chat.send",
	/** user surface → gateway: read synchronized session history (dsh session log mirror). */
	CHAT_HISTORY: "chat.history",
	/** user surface → gateway: list paired hosts with their last state digests. */
	HOST_LIST: "host.list"
};
const FedEvent = {
	/** pairing outcome for the requesting host (approved token / denied reason). */
	PAIR_RESULT: "pair/result",
	/** pairing code awaiting operator approval (gateway → user surfaces). */
	PAIR_PENDING: "pair/pending",
	/** agent.stream — streamed agent output for a task/chat turn. */
	AGENT_STREAM: "agent.stream",
	/** tool lifecycle mirrors (dsh tool/call, tool/result shape). */
	TOOL_CALL: "tool/call",
	TOOL_RESULT: "tool/result",
	/** host presence transitions (online/offline/busy). */
	PRESENCE: "presence",
	/** task lifecycle updates (pending/running/done/failed/cancelled). */
	TASK_UPDATED: "task/updated",
	/** host state digest broadcast. */
	HOST_STATE: "host/state"
};
FedMethod.AGENT_TASK, FedMethod.AGENT_TASK_CANCEL, FedMethod.PAIR_REQUEST, FedMethod.CHAT_SEND;
//#endregion
//#region src/registry.ts
/**
* Host registry + device token store (gateway side).
* Tokens are stored hashed only; identity resolution is the auth choke point.
*/
function isKnownCapValue(value) {
	return Object.values(FedCapability).includes(value);
}
var HostRegistry = class {
	#tokens = /* @__PURE__ */ new Map();
	#hosts = /* @__PURE__ */ new Map();
	#nextDeviceId = 1;
	#file;
	/**
	* Persist the registry (token HASHES + identities — never raw tokens) so a
	* gateway restart does not force re-pairing (D-013).
	*/
	setPersistence(file) {
		this.#file = file;
		if (file !== void 0 && existsSync(file)) try {
			const parsed = JSON.parse(readFileSync(file, "utf8"));
			for (const device of parsed.devices ?? []) {
				if (typeof device.tokenHash !== "string" || typeof device.deviceId !== "string") continue;
				const identity = {
					deviceId: device.deviceId,
					displayName: device.displayName,
					caps: device.caps.filter(isKnownCapValue),
					pairedAt: device.pairedAt
				};
				this.#tokens.set(device.tokenHash, {
					deviceId: identity.deviceId,
					identity,
					revoked: device.revoked === true
				});
			}
			if (typeof parsed.nextDeviceId === "number" && parsed.nextDeviceId > this.#nextDeviceId) this.#nextDeviceId = parsed.nextDeviceId;
		} catch {}
	}
	#persist() {
		if (this.#file === void 0) return;
		try {
			const devices = [...this.#tokens.entries()].map(([tokenHash, entry]) => ({
				tokenHash,
				deviceId: entry.deviceId,
				displayName: entry.identity.displayName,
				caps: entry.identity.caps,
				pairedAt: entry.identity.pairedAt,
				revoked: entry.revoked
			}));
			mkdirSync(dirname(this.#file), { recursive: true });
			writeFileSync(this.#file, JSON.stringify({
				nextDeviceId: this.#nextDeviceId,
				devices
			}, null, 2), "utf8");
		} catch {}
	}
	mintDeviceId() {
		return `host-${String(this.#nextDeviceId++).padStart(3, "0")}`;
	}
	/** Register a freshly approved device: hash-only token storage (D-004). */
	registerToken(deviceId, rawToken, identity) {
		this.#tokens.set(hashToken(rawToken), {
			deviceId,
			identity,
			revoked: false
		});
		this.#persist();
	}
	/** Revoke: token stops resolving immediately; the host must re-pair. */
	revoke(deviceId) {
		let revoked = false;
		for (const entry of this.#tokens.values()) if (entry.deviceId === deviceId && !entry.revoked) {
			entry.revoked = true;
			revoked = true;
		}
		if (revoked) this.#persist();
		return revoked;
	}
	/** DeviceTokenStore.resolve ??the ONLY identity source (?????? choke point). */
	resolve(token) {
		const hash = hashToken(token);
		const entry = this.#tokens.get(hash);
		if (entry === void 0 || entry.revoked) return void 0;
		return entry.identity;
	}
	/** Attach or re-attach a live connection for an authenticated host. */
	bind(identity, send) {
		this.#hosts.set(identity.deviceId, {
			identity,
			send,
			lastSeenMs: Date.now(),
			digest: this.#hosts.get(identity.deviceId)?.digest
		});
	}
	unbind(deviceId) {
		const state = this.#hosts.get(deviceId);
		if (state !== void 0) state.send = void 0;
	}
	touch(deviceId, digest) {
		const state = this.#hosts.get(deviceId);
		if (state !== void 0) {
			state.lastSeenMs = Date.now();
			state.digest = digest;
		}
	}
	list() {
		const digests = [];
		for (const [deviceId, state] of this.#hosts) digests.push(state.digest ?? {
			deviceId,
			displayName: state.identity.displayName,
			os: "unknown",
			lanAddress: "unknown",
			reportedAtMs: state.lastSeenMs
		});
		return digests;
	}
	/** Resolve a host by deviceId or displayName for dispatch. */
	findForDispatch(nameOrId) {
		const direct = this.#hosts.get(nameOrId);
		if (direct !== void 0 && direct.send !== void 0) return direct;
		for (const state of this.#hosts.values()) if (state.identity.displayName === nameOrId && state.send !== void 0) return state;
	}
	hasCap(deviceId, cap) {
		return this.#hosts.get(deviceId)?.identity.caps.includes(cap) ?? false;
	}
};
//#endregion
export { FedMethod as a, fedError as c, negotiateProtocol as d, toFedError as f, FedEvent as i, hashToken as l, FedCapability as n, asDeviceToken as o, tokenHashesEqual as p, FedErrorCode as r, decodeFrame as s, HostRegistry as t, issueDeviceToken as u };

//# sourceMappingURL=registry-nMjdy06R.js.map