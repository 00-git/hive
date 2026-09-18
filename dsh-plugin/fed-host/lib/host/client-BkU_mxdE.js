import { AuditLog } from "./audit.js";
import { runOp } from "./ops.js";
import { WebSocket } from "ws";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { freemem, homedir, hostname, platform, totalmem, uptime } from "node:os";
import { join } from "node:path";
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
//#region src/client.ts
/**
* hive-fed-host client: gateway connection lifecycle.
*
* connect (token if stored) ??hello
*   ??? ok            ??authenticated: register, report state, execute tasks
*   ??? ok + pairing  ??pending: wait pair/result event, persist token, reconnect
* Reconnect with exponential backoff + jitter; every decision audited.
*/
var HostClient = class {
	#cfg;
	#audit;
	#ws;
	#attempt = 0;
	#closedByUs = false;
	#pending = /* @__PURE__ */ new Map();
	#stateTimer;
	constructor(config = {}) {
		const stateDir = config.stateDir ?? join(homedir(), ".hive");
		this.#cfg = {
			gatewayUrl: config.gatewayUrl ?? "ws://127.0.0.1:3081/fed",
			deviceName: config.deviceName ?? hostname(),
			stateDir,
			stateIntervalMs: config.stateIntervalMs ?? 15e3,
			whitelistDirs: config.whitelistDirs ?? [process.cwd()]
		};
		this.#audit = new AuditLog(join(stateDir, "host-audit.log"));
	}
	start() {
		this.#connect();
	}
	stop() {
		this.#closedByUs = true;
		if (this.#stateTimer !== void 0) clearInterval(this.#stateTimer);
		this.#ws?.close();
	}
	#tokenFile() {
		return join(this.#cfg.stateDir, "device-token.json");
	}
	#loadToken() {
		const file = this.#tokenFile();
		if (!existsSync(file)) return void 0;
		try {
			const parsed = JSON.parse(readFileSync(file, "utf8"));
			if (typeof parsed.token === "string" && typeof parsed.deviceId === "string") return parsed;
			return;
		} catch {
			return;
		}
	}
	#discardToken() {
		const file = this.#tokenFile();
		if (existsSync(file)) {
			try {
				const parsed = JSON.parse(readFileSync(file, "utf8"));
				writeFileSync(`${file}.stale`, JSON.stringify(parsed, null, 2), "utf8");
			} catch {}
			try {
				unlinkSync(file);
			} catch {}
		}
	}
	#saveToken(stored) {
		mkdirSync(this.#cfg.stateDir, { recursive: true });
		writeFileSync(this.#tokenFile(), JSON.stringify(stored, null, 2), "utf8");
	}
	#connect() {
		this.#loadToken();
		const ws = new WebSocket(this.#cfg.gatewayUrl);
		this.#ws = ws;
		ws.on("open", () => {
			this.#attempt = 0;
			const stored = this.#loadToken();
			this.#request(ws, FedMethod.CONNECT, {
				role: "host",
				deviceName: this.#cfg.deviceName,
				protocol: {
					min: 1,
					max: 1
				},
				deviceToken: stored?.token,
				caps: Object.values(FedCapability)
			}).then((payload) => {
				const hello = payload;
				if (hello.pairing !== void 0) {
					console.log(`[hive-fed-host] pairing required: present code ${hello.pairing.code} to the operator`);
					this.#audit.write({
						ts: Date.now(),
						actor: this.#cfg.deviceName,
						action: "pair.wait",
						target: "gateway",
						decision: "info",
						detail: { code: hello.pairing.code }
					});
					return;
				}
				if (stored !== void 0) this.#onAuthenticated(ws, stored);
			}).catch((error) => {
				const message = error instanceof Error ? error.message : JSON.stringify(error);
				console.error(`[hive-fed-host] connect rejected: ${message}`);
				if (message.includes("unauthenticated") && stored !== void 0) {
					this.#discardToken();
					this.#audit.write({
						ts: Date.now(),
						actor: this.#cfg.deviceName,
						action: "token.discard",
						target: "gateway",
						decision: "info"
					});
				}
				ws.close();
			});
		});
		ws.on("message", (data) => {
			let frame;
			try {
				frame = decodeFrame(JSON.parse(String(data)));
			} catch (error) {
				this.#audit.write({
					ts: Date.now(),
					actor: "gateway",
					action: "frame.invalid",
					target: "host",
					decision: "deny",
					detail: String(error)
				});
				return;
			}
			if (frame.type === "req") {
				this.#handleRequest(ws, frame);
				return;
			}
			if (frame.type === "res") {
				const pending = this.#pending.get(frame.id);
				if (pending !== void 0) {
					this.#pending.delete(frame.id);
					if (frame.ok) pending.resolve(frame.payload);
					else pending.reject(frame.error);
				}
				return;
			}
			if (frame.type === "event" && frame.event === FedEvent.PAIR_RESULT) {
				const payload = frame.payload;
				if (payload.ok === true && typeof payload.token === "string" && typeof payload.deviceId === "string") {
					this.#saveToken({
						deviceId: payload.deviceId,
						token: payload.token,
						deviceName: payload.deviceName ?? this.#cfg.deviceName
					});
					this.#audit.write({
						ts: Date.now(),
						actor: this.#cfg.deviceName,
						action: "pair.approved",
						target: payload.deviceId,
						decision: "allow"
					});
					console.log(`[hive-fed-host] paired as ${payload.deviceId} (${payload.deviceName}); reconnecting with token`);
					ws.close();
					setTimeout(() => this.#connect(), 300);
				}
			}
		});
		ws.on("close", () => {
			if (this.#closedByUs) return;
			const delay = Math.min(3e4, 500 * 2 ** this.#attempt) + Math.floor(Math.random() * 250);
			this.#attempt += 1;
			console.log(`[hive-fed-host] disconnected; reconnecting in ${delay}ms (attempt ${this.#attempt})`);
			setTimeout(() => this.#connect(), delay);
		});
		ws.on("error", (error) => {
			console.error(`[hive-fed-host] ws error: ${error.message}`);
		});
	}
	#onAuthenticated(ws, stored) {
		console.log(`[hive-fed-host] authenticated as ${stored.deviceId} (${stored.deviceName})`);
		this.#audit.write({
			ts: Date.now(),
			actor: this.#cfg.deviceName,
			action: "connect.host",
			target: stored.deviceId,
			decision: "allow"
		});
		this.#request(ws, FedMethod.HOST_REGISTER, { digest: this.#stateDigest() }).catch(() => void 0);
		if (this.#stateTimer === void 0) this.#stateTimer = setInterval(() => {
			if (ws.readyState === WebSocket.OPEN) this.#request(ws, FedMethod.HOST_STATE_REPORT, { digest: this.#stateDigest() }).catch(() => void 0);
		}, this.#cfg.stateIntervalMs);
	}
	#stateDigest() {
		return {
			os: `${platform()} ${hostname()}`,
			lanAddress: "loopback-mvp",
			memTotalMb: Math.round(totalmem() / 1024 / 1024),
			memFreeMb: Math.round(freemem() / 1024 / 1024),
			uptimeSec: Math.floor(uptime())
		};
	}
	async #handleRequest(ws, req) {
		if (req.method === FedMethod.AGENT_TASK) {
			const params = req.params ?? {};
			const traceId = typeof req.traceId === "string" ? req.traceId : void 0;
			if (typeof req.deadlineMs === "number" && Date.now() > req.deadlineMs) {
				this.#reply(ws, req.id, false, void 0, {
					code: FedErrorCode.DEADLINE_EXCEEDED,
					message: "deadline already elapsed",
					traceId
				});
				return;
			}
			try {
				const { op, args } = parsePromptSafe(typeof params.prompt === "string" ? params.prompt : "");
				const result = await runOp({
					whitelistDirs: this.#cfg.whitelistDirs,
					audit: this.#audit,
					maxReadBytes: 1e6
				}, traceId ?? "", op, args);
				this.#reply(ws, req.id, true, {
					taskId: params.taskId,
					...result
				});
			} catch (error) {
				this.#reply(ws, req.id, false, void 0, {
					code: FedErrorCode.PAYLOAD_INVALID,
					message: error instanceof Error ? error.message : String(error),
					traceId
				});
			}
			return;
		}
		if (req.method === FedMethod.AGENT_TASK_CANCEL) {
			this.#audit.write({
				ts: Date.now(),
				actor: "gateway",
				action: "task.cancel",
				target: JSON.stringify((req.params ?? {}).taskId ?? ""),
				decision: "info"
			});
			this.#reply(ws, req.id, true, { cancelled: true });
			return;
		}
		this.#reply(ws, req.id, false, void 0, {
			code: FedErrorCode.METHOD_UNKNOWN,
			message: `host does not mount ${req.method}`
		});
	}
	#reply(ws, id, ok, payload, error) {
		ws.send(JSON.stringify({
			type: "res",
			id,
			ok,
			...ok ? { payload } : { error }
		}));
	}
	#request(ws, method, params, extra) {
		const id = `h-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		return new Promise((resolve, reject) => {
			this.#pending.set(id, {
				resolve,
				reject
			});
			ws.send(JSON.stringify({
				type: "req",
				id,
				method,
				params,
				...extra,
				traceId: `host-${Date.now()}`
			}));
		});
	}
};
function parsePromptSafe(prompt) {
	const parsed = JSON.parse(prompt);
	if (typeof parsed !== "object" || parsed === null || typeof parsed.op !== "string") throw new Error("prompt must be a JSON object with an op field");
	const { op, ...rest } = parsed;
	return {
		op,
		args: rest
	};
}
//#endregion
export { HostClient as t };

//# sourceMappingURL=client-BkU_mxdE.js.map