import { a as FedMethod, c as fedError, d as negotiateProtocol, f as toFedError, i as FedEvent, l as hashToken, n as FedCapability, o as asDeviceToken, p as tokenHashesEqual, r as FedErrorCode, s as decodeFrame, t as HostRegistry, u as issueDeviceToken } from "./registry-nMjdy06R.js";
import { AuditLog } from "./audit.js";
import { PairingManager } from "./pairing.js";
import { WebSocket, WebSocketServer } from "ws";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
//#region src/server.ts
/**
* hive-fed-gateway server: role-based WS handshake (host | user), host registry,
* pairing (code ??approve ??token, revocable), directed dispatch with
* idempotency + deadlines + cancel, event seq/ack backpressure, JSONL audit
* on every cross-trust-boundary decision.
*/
var GatewayServer = class {
	#cfg;
	#audit;
	#registry = new HostRegistry();
	#pairing = new PairingManager();
	#conns = /* @__PURE__ */ new Set();
	#tasks = /* @__PURE__ */ new Map();
	#idempotency = /* @__PURE__ */ new Map();
	#pendingUserReplies = /* @__PURE__ */ new Map();
	#userToken;
	#wss;
	constructor(config = {}) {
		const stateDir = config.stateDir ?? join(homedir(), ".hive");
		this.#cfg = {
			port: config.port ?? 3081,
			bindHost: config.bindHost ?? "127.0.0.1",
			auditPath: config.auditPath ?? join(stateDir, "audit.log"),
			stateDir
		};
		this.#audit = new AuditLog(this.#cfg.auditPath);
		const userTokenFile = join(stateDir, "gateway-user-token");
		this.#userToken = existsSync(userTokenFile) ? readFileSync(userTokenFile, "utf8").trim() : issueDeviceToken("gateway-user").token;
		this.#registry.setPersistence(join(stateDir, "device-registry.json"));
	}
	get userToken() {
		return this.#userToken;
	}
	start() {
		this.#wss = new WebSocketServer({
			port: this.#cfg.port,
			host: this.#cfg.bindHost
		});
		this.#wss.on("connection", (ws) => this.#onConnection(ws));
		this.#wss.on("error", (error) => {
			console.error(`[hive-fed-gateway] server error: ${error.message}`);
		});
		this.#wss.on("close", () => {
			console.error("[hive-fed-gateway] server CLOSED (unexpected unless stop())");
		});
		writeUserTokenFile(this.#cfg.stateDir, this.#userToken);
		console.log(`[hive-fed-gateway] listening on ws://${this.#cfg.bindHost}:${this.#cfg.port}/fed pid=${process.pid}`);
		console.log(`[hive-fed-gateway] user token file: ${join(this.#cfg.stateDir, "gateway-user-token")}`);
	}
	stop() {
		for (const task of this.#tasks.values()) clearTimeout(task.timer);
		this.#wss?.close();
		for (const conn of this.#conns) conn.ws.terminate();
	}
	#onConnection(ws) {
		const conn = {
			ws,
			role: "pending-host",
			deviceName: "unidentified",
			outSeq: 0,
			ackedThrough: 0
		};
		this.#conns.add(conn);
		ws.on("message", (data) => {
			let raw;
			try {
				raw = JSON.parse(String(data));
			} catch {
				this.#replyError(conn, "?", fedError(FedErrorCode.PAYLOAD_INVALID, "frames must be JSON"));
				return;
			}
			try {
				const frame = decodeFrame(raw);
				this.#handleFrame(conn, frame);
			} catch (error) {
				const err = toFedError(error);
				const rawId = raw !== null && typeof raw === "object" && typeof raw.id === "string" ? raw.id : "?";
				this.#replyError(conn, rawId, fedError(FedErrorCode.INTERNAL, err.message));
				this.#audit.write({
					ts: Date.now(),
					actor: conn.deviceName,
					action: "frame.error",
					target: "gateway",
					decision: "deny",
					detail: err.message
				});
			}
		});
		ws.on("close", () => {
			this.#conns.delete(conn);
			if (conn.role === "host" && conn.identity !== void 0) {
				this.#registry.unbind(conn.identity.deviceId);
				this.#broadcastToUsers({
					type: "event",
					event: FedEvent.PRESENCE,
					payload: {
						deviceId: conn.identity.deviceId,
						presence: "offline"
					}
				});
			}
		});
	}
	#handleFrame(conn, frame) {
		if (frame.type === "event.ack") {
			conn.ackedThrough = frame.ackedThrough;
			return;
		}
		if (frame.type === "event") return;
		if (frame.type === "res") {
			if (this.#pendingUserReplies.get(frame.id) !== void 0) {
				const asReq = {
					...frame,
					method: FedMethod.AGENT_TASK
				};
				this.#relayHostResult(conn, asReq, frame.ok, frame.payload, frame.error);
			}
			return;
		}
		if (frame.method === FedMethod.CONNECT) {
			this.#handleConnect(conn, frame);
			return;
		}
		if (conn.role === "pending-host") {
			this.#replyError(conn, frame.id, fedError(FedErrorCode.UNAUTHENTICATED, "connect first"));
			return;
		}
		switch (frame.method) {
			case FedMethod.PAIR_APPROVE: return this.#handlePairApprove(conn, frame);
			case FedMethod.HOST_LIST: return this.#replyOk(conn, frame.id, { hosts: this.#registry.list() });
			case FedMethod.AGENT_TASK: return this.#handleTaskDispatch(conn, frame);
			case FedMethod.AGENT_TASK_CANCEL: return this.#handleTaskCancel(conn, frame);
			case FedMethod.HOST_STATE_REPORT: return this.#handleHostReport(conn, frame);
			default: this.#replyError(conn, frame.id, fedError(FedErrorCode.METHOD_UNKNOWN, `unknown method ${frame.method}`));
		}
	}
	#handleConnect(conn, req) {
		const params = req.params ?? {};
		if (params.role !== "host" && params.role !== "user") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, "role must be host | user"));
			return;
		}
		try {
			negotiateProtocol({
				role: params.role,
				deviceName: params.deviceName ?? "",
				protocol: params.protocol ?? {
					min: 1,
					max: 1
				}
			});
		} catch (error) {
			this.#replyError(conn, req.id, error);
			return;
		}
		conn.deviceName = typeof params.deviceName === "string" && params.deviceName.length > 0 ? params.deviceName.slice(0, 64) : "unidentified";
		if (params.role === "user") {
			if (!tokenMatches(typeof params.deviceToken === "string" ? params.deviceToken : "", this.#userToken)) {
				this.#audit.write({
					ts: Date.now(),
					actor: conn.deviceName,
					action: "connect.user",
					target: "gateway",
					decision: "deny",
					detail: "bad user token"
				});
				this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, "user token required"));
				conn.ws.close();
				return;
			}
			conn.role = "user";
			this.#replyOk(conn, req.id, {
				protocol: 1,
				peer: {
					role: "user",
					deviceName: conn.deviceName
				},
				serverTimeMs: Date.now()
			});
			this.#audit.write({
				ts: Date.now(),
				actor: conn.deviceName,
				action: "connect.user",
				target: "gateway",
				decision: "allow"
			});
			return;
		}
		const token = asDeviceToken(params.deviceToken);
		if (token !== void 0) {
			const identity = this.#registry.resolve(token);
			if (identity === void 0) {
				this.#audit.write({
					ts: Date.now(),
					actor: conn.deviceName,
					action: "connect.host",
					target: "gateway",
					decision: "deny",
					detail: "unknown or revoked token"
				});
				this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, "unknown or revoked device token"));
				conn.ws.close();
				return;
			}
			conn.role = "host";
			conn.identity = identity;
			this.#registry.bind(identity, (frame) => this.#send(conn, frame));
			this.#replyOk(conn, req.id, {
				protocol: 1,
				peer: {
					role: "host",
					deviceName: identity.displayName
				},
				serverTimeMs: Date.now()
			});
			this.#broadcastToUsers({
				type: "event",
				event: FedEvent.PRESENCE,
				payload: {
					deviceId: identity.deviceId,
					presence: "online"
				}
			});
			this.#audit.write({
				ts: Date.now(),
				actor: identity.displayName,
				action: "connect.host",
				target: identity.deviceId,
				decision: "allow"
			});
			return;
		}
		const pending = this.#pairing.create(conn.deviceName, Array.isArray(params.caps) ? params.caps : []);
		conn.role = "pending-host";
		conn.pairCode = pending.code;
		this.#replyOk(conn, req.id, {
			protocol: 1,
			peer: {
				role: "host",
				deviceName: conn.deviceName
			},
			serverTimeMs: Date.now(),
			pairing: {
				code: pending.code,
				expiresAtMs: pending.expiresAtMs
			}
		});
		this.#broadcastToUsers({
			type: "event",
			event: FedEvent.PAIR_PENDING,
			payload: {
				code: pending.code,
				deviceName: pending.deviceName,
				expiresAtMs: pending.expiresAtMs
			}
		});
		console.log(`[hive-fed-gateway] pairing pending: code ${pending.code} for "${pending.deviceName}"`);
		this.#audit.write({
			ts: Date.now(),
			actor: conn.deviceName,
			action: "pair.request",
			target: "gateway",
			decision: "info",
			detail: { code: pending.code }
		});
	}
	#handlePairApprove(conn, req) {
		const params = req.params ?? {};
		if (conn.role !== "user") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, "only user surfaces approve pairings"));
			return;
		}
		const result = this.#pairing.approve(typeof params.code === "string" ? params.code : "", conn.deviceName);
		if (!result.ok) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, result.reason));
			this.#audit.write({
				ts: Date.now(),
				actor: conn.deviceName,
				action: "pair.approve",
				target: params.code ?? "?",
				decision: "deny",
				detail: result.reason
			});
			return;
		}
		const deviceId = this.#registry.mintDeviceId();
		const issued = issueDeviceToken(deviceId);
		const identity = {
			deviceId,
			displayName: result.pending.deviceName,
			caps: result.pending.caps.filter(isKnownCap),
			pairedAt: Date.now()
		};
		this.#registry.registerToken(deviceId, issued.token, identity);
		for (const other of this.#conns) if (other.role === "pending-host" && other.pairCode === result.pending.code) {
			this.#send(other, {
				type: "event",
				event: FedEvent.PAIR_RESULT,
				payload: {
					ok: true,
					token: issued.token,
					deviceId,
					deviceName: identity.displayName
				}
			});
			break;
		}
		this.#replyOk(conn, req.id, {
			deviceId,
			deviceName: identity.displayName,
			caps: identity.caps
		});
		this.#audit.write({
			ts: Date.now(),
			actor: conn.deviceName,
			action: "pair.approve",
			target: deviceId,
			decision: "allow",
			detail: {
				deviceName: identity.displayName,
				caps: identity.caps
			}
		});
	}
	#handleHostReport(conn, req) {
		if (conn.role !== "host" || conn.identity === void 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, "host identity required"));
			return;
		}
		const rawDigest = req.params ?? {};
		const digest = {
			deviceId: conn.identity.deviceId,
			displayName: conn.identity.displayName,
			os: typeof rawDigest.os === "string" ? rawDigest.os.slice(0, 64) : "unknown",
			lanAddress: typeof rawDigest.lanAddress === "string" ? rawDigest.lanAddress.slice(0, 64) : "unknown",
			cpuLoadPct: typeof rawDigest.cpuLoadPct === "number" ? rawDigest.cpuLoadPct : void 0,
			memTotalMb: typeof rawDigest.memTotalMb === "number" ? rawDigest.memTotalMb : void 0,
			memFreeMb: typeof rawDigest.memFreeMb === "number" ? rawDigest.memFreeMb : void 0,
			reportedAtMs: Date.now()
		};
		this.#registry.touch(conn.identity.deviceId, digest);
		this.#replyOk(conn, req.id, { recorded: true });
		this.#broadcastToUsers({
			type: "event",
			event: FedEvent.HOST_STATE,
			payload: digest
		});
	}
	#handleTaskDispatch(conn, req) {
		if (conn.role !== "user") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, "only user surfaces dispatch tasks"));
			return;
		}
		const params = req.params ?? {};
		if (typeof params.prompt !== "string" || params.prompt.length === 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, "prompt required"));
			return;
		}
		if (typeof req.idempotencyKey !== "string" || req.idempotencyKey.length === 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, "agent.task requires idempotencyKey"));
			return;
		}
		const replayKey = `${conn.deviceName}:${req.idempotencyKey}`;
		const replay = this.#idempotency.get(replayKey);
		if (replay !== void 0 && replay.res !== void 0) {
			this.#replyOk(conn, req.id, replay.res);
			return;
		}
		const target = this.#registry.findForDispatch(params.host ?? "");
		if (target === void 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, `host ${params.host ?? "?"} not online`));
			return;
		}
		if (!this.#registry.hasCap(target.identity.deviceId, FedCapability.TASK_EXEC)) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, `host ${target.identity.displayName} lacks task.exec`));
			return;
		}
		const traceId = typeof params.traceId === "string" && params.traceId.length > 0 ? params.traceId : `t-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const deadlineMs = typeof params.deadlineMs === "number" && params.deadlineMs > 0 ? params.deadlineMs : 3e4;
		const timer = setTimeout(() => {
			if (this.#tasks.delete(taskId)) {
				this.#pendingUserReplies.delete(`gw-${taskId}`);
				this.#replyError(conn, req.id, fedError(FedErrorCode.DEADLINE_EXCEEDED, `task exceeded ${deadlineMs}ms`, { traceId }));
				this.#audit.write({
					ts: Date.now(),
					traceId,
					actor: "gateway",
					action: "agent.task",
					target: target.identity.displayName,
					decision: "deny",
					detail: "deadline"
				});
			}
		}, deadlineMs);
		this.#tasks.set(taskId, {
			taskId,
			traceId,
			hostDeviceId: target.identity.deviceId,
			timer
		});
		this.#pendingUserReplies.set(`gw-${taskId}`, {
			conn,
			reqId: req.id,
			taskId,
			traceId,
			replayKey
		});
		target.send({
			type: "req",
			id: `gw-${taskId}`,
			method: FedMethod.AGENT_TASK,
			params: {
				taskId,
				prompt: params.prompt,
				requiredCaps: [FedCapability.TASK_EXEC],
				deadlineMs,
				traceId
			},
			deadlineMs: Date.now() + deadlineMs,
			idempotencyKey: req.idempotencyKey,
			traceId
		});
		this.#audit.write({
			ts: Date.now(),
			traceId,
			actor: conn.deviceName,
			action: "agent.task",
			target: target.identity.displayName,
			decision: "allow",
			detail: {
				taskId,
				prompt: params.prompt.slice(0, 200)
			}
		});
	}
	#handleTaskCancel(conn, req) {
		const params = req.params ?? {};
		const task = typeof params.taskId === "string" ? this.#tasks.get(params.taskId) : void 0;
		if (task === void 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, "task not in flight"));
			return;
		}
		[...this.#conns].find((c) => c.identity?.deviceId === task.hostDeviceId)?.send({
			type: "req",
			id: `cancel-${task.taskId}`,
			method: FedMethod.AGENT_TASK_CANCEL,
			params: {
				taskId: task.taskId,
				traceId: task.traceId
			},
			traceId: task.traceId
		});
		this.#replyOk(conn, req.id, { cancelling: task.taskId });
		this.#audit.write({
			ts: Date.now(),
			traceId: task.traceId,
			actor: conn.deviceName,
			action: "agent.task.cancel",
			target: task.taskId,
			decision: "allow"
		});
	}
	/** Relay a host's task result back to the initiating user surface. */
	#relayHostResult(conn, req, ok, payload, error) {
		const pending = this.#pendingUserReplies.get(req.id);
		if (pending === void 0) return;
		this.#pendingUserReplies.delete(req.id);
		const task = this.#tasks.get(pending.taskId);
		if (task !== void 0) {
			clearTimeout(task.timer);
			this.#tasks.delete(pending.taskId);
		}
		if (ok) this.#idempotency.set(pending.replayKey, { res: payload });
		if (ok) this.#replyOk(pending.conn, pending.reqId, payload);
		else this.#replyError(pending.conn, pending.reqId, toFedError(error, pending.traceId));
		this.#audit.write({
			ts: Date.now(),
			traceId: pending.traceId,
			actor: conn.identity?.displayName ?? "host",
			action: "agent.task.result",
			target: pending.taskId,
			decision: ok ? "allow" : "deny"
		});
	}
	#replyOk(conn, id, payload) {
		this.#send(conn, {
			type: "res",
			id,
			ok: true,
			payload
		});
	}
	#replyError(conn, id, error) {
		this.#send(conn, {
			type: "res",
			id,
			ok: false,
			error
		});
	}
	#send(conn, frame) {
		if (frame.type === "event") frame.seq = ++conn.outSeq;
		if (conn.ws.readyState === WebSocket.OPEN) conn.ws.send(JSON.stringify(frame));
	}
	#broadcastToUsers(frame) {
		for (const conn of this.#conns) if (conn.role === "user") this.#send(conn, { ...frame });
	}
};
function isKnownCap(value) {
	return Object.values(FedCapability).includes(value);
}
/** Constant-time comparison over SHA-256 hashes (never raw secrets). */
function tokenMatches(presented, expected) {
	return tokenHashesEqual(hashToken(presented), hashToken(expected));
}
function writeUserTokenFile(stateDir, token) {
	mkdirSync(stateDir, { recursive: true });
	writeFileSync(join(stateDir, "gateway-user-token"), token, "utf8");
}
//#endregion
export { GatewayServer };

//# sourceMappingURL=server.js.map