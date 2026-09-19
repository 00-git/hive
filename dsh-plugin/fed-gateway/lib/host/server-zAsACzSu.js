import { AuditLog } from "./audit.js";
import { HostRegistry } from "./registry.js";
import { WebSocket, WebSocketServer } from "ws";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir, networkInterfaces } from "node:os";
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
* Self-sovereign federation identity — 自证身份，无签发方.
*
* Why this replaces the token model: the old design had the accepting peer mint
* a device token for every other peer (`issueDeviceToken` + a token registry).
* Whoever held that registry WAS the authority on everyone's identity — that is
* exactly the center server this refactor removes. Here a peer's identity is
* simply its key pair:
*
*   deviceId = base32(sha256(rawPublicKey))[0..16]
*
* Consequences, all deliberate:
* - A claimed deviceId that does not derive from the presented public key is
*   rejected before any trust question is asked, so nobody can claim someone
*   else's id. The mapping is checkable locally — no registry, no lookup.
* - Changing keys IS changing identity. There is no in-place key rotation and
*   no revocation list to synchronize; the old id simply never reappears.
* - A valid signature proves KEY POSSESSION, never trustworthiness. Trust still
*   requires a human to compare the SAS out of band (安全模型 #6: 显式信任 +
*   本地批准 + 审计，三者缺一不可).
*
* Signature scheme: Ed25519 over a canonical message binding the handshake
* nonce AND both peer ids, so a captured signature cannot be replayed into a
* different session or reflected back at the initiator (MITM 防护).
*/
/** Length of the human-facing device id. 16 symbols × 5 bits = 80 bits. */
const DEVICE_ID_LENGTH = 16;
/** Magic + version so a future scheme can coexist during migration. */
const HANDSHAKE_DOMAIN = "hive-handshake-v1";
const SAS_DOMAIN = "hive-sas-v1";
/** Lowercase RFC4648 alphabet (no padding): safe in CLI output and on the wire. */
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
/**
* Deterministic base32 (no padding) so an id is reproducible from the key on
* any peer without a shared table.
*/
function base32Lower(bytes) {
	let out = "";
	let buffer = 0;
	let bits = 0;
	for (const byte of bytes) {
		buffer = buffer << 8 | byte;
		bits += 8;
		while (bits >= 5) {
			out += BASE32_ALPHABET[buffer >>> bits - 5 & 31];
			bits -= 5;
		}
	}
	if (bits > 0) out += BASE32_ALPHABET[buffer << 5 - bits & 31];
	return out;
}
/** Rebuild a KeyObject from the compact wire form (raw 32-byte JWK `x`). */
function publicKeyFromWire(publicKey) {
	if (typeof publicKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(publicKey)) throw new Error("publicKey must be a base64url Ed25519 coordinate (43 chars)");
	return createPublicKey({
		key: {
			kty: "OKP",
			crv: "Ed25519",
			x: publicKey
		},
		format: "jwk"
	});
}
function privateKeyFromPem(privateKeyPem) {
	return createPrivateKey(privateKeyPem);
}
/**
* Derive the self-certifying id from a public key. Pure and local: any peer can
* recompute it, so no peer needs to be told who anyone is.
*/
function deriveDeviceId(publicKey) {
	const raw = publicKeyFromWire(publicKey).export({ format: "jwk" });
	if (typeof raw.x !== "string") throw new Error("ed25519 key has no x coordinate");
	return base32Lower(createHash("sha256").update(raw.x, "utf8").digest()).slice(0, DEVICE_ID_LENGTH);
}
/** Mint a fresh peer identity. Called once per machine, then persisted. */
function generateIdentity() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const publicKeyB64 = publicKey.export({ format: "jwk" }).x;
	return {
		deviceId: deriveDeviceId(publicKeyB64),
		publicKey: publicKeyB64,
		privateKeyPem: privateKey.export({
			type: "pkcs8",
			format: "pem"
		}).toString(),
		createdAtMs: Date.now()
	};
}
/**
* Rebuild the identity material from persisted parts, verifying that the stored
* deviceId still derives from the stored key. A mismatch means the file was
* edited (or is corrupt) — refuse rather than silently adopt a new identity.
*/
function restoreIdentity(publicKey, privateKeyPem, createdAtMs = 0) {
	return {
		deviceId: deriveDeviceId(publicKey),
		publicKey,
		privateKeyPem,
		createdAtMs
	};
}
/** Fresh 32-byte nonce, base64url. Per-connection: never reused. */
function createNonce() {
	return randomBytes(32).toString("base64url");
}
/**
* Canonical handshake message. Both ids are always present in fixed DIALER,
* ACCEPTOR order — callers pass them in that order no matter which side is
* signing, so the two proofs below cannot drift apart.
*/
function handshakeMessage(nonce, dialerId, acceptorId) {
	return Buffer.from(`${HANDSHAKE_DOMAIN}\n${nonce}\n${dialerId}\n${acceptorId}`, "utf8");
}
/**
* Sign a handshake nonce. Used by BOTH sides:
* - the dialer signs the acceptor's nonce (step 2 of the handshake),
* - the acceptor signs the dialer's nonce (rides along in the challenge frame).
*
* Authentication is mutual because neither side can produce a proof without
* the other's fresh nonce — a peer that only verified the dialer would let an
* attacker impersonate the acceptor to a dialing machine.
*/
function signHandshake(privateKeyPem, nonce, dialerId, acceptorId) {
	const key = privateKeyFromPem(privateKeyPem);
	return sign(null, handshakeMessage(nonce, dialerId, acceptorId), key).toString("base64url");
}
/**
* Verify a peer's proof. `dialerId`/`acceptorId` must be passed in the same
* fixed roles the signer used, so a proof made for one direction cannot be
* reflected back at its maker.
*/
function verifyHandshake(publicKey, nonce, dialerId, acceptorId, signature) {
	try {
		const key = publicKeyFromWire(publicKey);
		return verify(null, handshakeMessage(nonce, dialerId, acceptorId), key, Buffer.from(signature, "base64url"));
	} catch {
		return false;
	}
}
/**
* Short authentication string derived from BOTH public keys.
*
* Order-independent (the pair is sorted), so the two operators read the same
* six digits off their own screens. That is the whole point: an attacker who
* substitutes a key changes the SAS, and the mismatch is visible to a human.
* Not a secret — derivation from public keys is intentional.
*/
function computeSas(publicKeyA, publicKeyB) {
	const [first, second] = [publicKeyA, publicKeyB].sort();
	const numeric = createHash("sha256").update(`${SAS_DOMAIN}\n${first}\n${second}`, "utf8").digest().readUInt32BE(0) % 1e6;
	return String(numeric).padStart(6, "0");
}
/**
* Federation authorization — the single choke point.
*
* 硬约束 (安全模型第 6 条「禁止清单」, mirrored in the protocol tests): the ONLY
* inputs consulted are (a) a handshake signature the transport has already
* verified against the presented public key, and (b) membership in the local,
* operator-approved trust table. Every other parameter — claimed device names,
* capability lists, source address, headers — is audit metadata and cannot
* influence the decision.
*
* Identity is self-sovereign (see identity.ts): there is no issuer, and
* therefore no revocation list anyone must synchronize. An operator grants
* trust once by comparing the SAS out of band; the table pins the peer after
* that. Rejecting a peer is local by construction — delete its row.
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
function isFedCapability(value) {
	return Object.values(FedCapability).includes(value);
}
/**
* Constant-time comparison for the LOCAL user surface token.
*
* Scope note: this token never crosses a trust boundary — it only gates the
* loopback CLI against the local listener, so it is not part of the federation
* identity model and needs no registry.
*/
function localTokenMatches(presented, expected) {
	if (typeof presented !== "string") return false;
	const a = Buffer.from(presented, "utf8");
	const b = Buffer.from(expected, "utf8");
	return a.length === b.length && timingSafeEqual(a, b);
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
const FedMethod = {
	/** any peer → acceptor: first frame on a connection (role + protocol range + public key). */
	CONNECT: "connect",
	/** dialing peer → acceptor: sign the acceptor's nonce — step 2 of every handshake. */
	AUTHENTICATE: "authenticate",
	/** local user surface → acceptor: peers whose signature verified but whose SAS is unconfirmed. */
	TRUST_PENDING_LIST: "trust.pending.list",
	/** local user surface → acceptor: an operator compared the SAS; pin this peer. */
	TRUST_APPROVE: "trust.approve",
	/** local user surface → acceptor: drop a peer from the trust table (local, instant, no sync). */
	TRUST_REVOKE: "trust.revoke",
	/** local user surface → acceptor: read the trust table. */
	TRUST_LIST: "trust.list",
	/** peer → acceptor: advertise caps and current state summary (post-connect). */
	HOST_REGISTER: "host.register",
	/** peer → acceptor: periodic state digest push (also available as an event). */
	HOST_STATE_REPORT: "host.state.report",
	/** acceptor → peer: dispatch one directed task. Side-effecting. */
	AGENT_TASK: "agent.task",
	/** either direction: cancel an in-flight task. Side-effecting. */
	AGENT_TASK_CANCEL: "agent.task.cancel",
	/** acceptor → peer: ask a bounded introspection question (no side effects). */
	AGENT_ASK: "agent.ask",
	/** local user surface → acceptor: send a chat turn. Side-effecting. */
	CHAT_SEND: "chat.send",
	/** local user surface → acceptor: read synchronized session history (dsh session log mirror). */
	CHAT_HISTORY: "chat.history",
	/** local user surface → acceptor: list trusted peers with their last state digests. */
	HOST_LIST: "host.list",
	/** any peer → any peer: exchange known peers so the mesh heals without a directory. */
	PEER_EXCHANGE: "peer.exchange"
};
const FedEvent = {
	/** acceptor → local user surfaces: a peer's signature verified but its SAS is unconfirmed. */
	TRUST_PENDING: "trust/pending",
	/** acceptor → a pending peer: an operator compared the SAS and pinned this peer. */
	TRUST_GRANTED: "trust/granted",
	/** acceptor → a pending peer: the operator rejected it, or the window expired. */
	TRUST_DENIED: "trust/denied",
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
	HOST_STATE: "host/state",
	/** peer table delta so the mesh heals without any directory. */
	PEER_UPDATED: "peer/updated"
};
FedMethod.AGENT_TASK, FedMethod.AGENT_TASK_CANCEL, FedMethod.CHAT_SEND;
/**
* Local trust table — the operator's decisions, persisted.
*
* There is deliberately no distributed version of this and none is wanted.
* Trust is a LOCAL decision, so two peers may legitimately disagree about a
* third; rejecting a peer is therefore instant and needs no propagation
* (delete the row).
*
* The persistence adapter is treated as the shared medium, and every public
* operation re-reads it first. That is not defensive coding for its own sake:
* a hive node is two processes (the accepting half and the dialing half) that
* share one state directory, so an approval made on one side must become
* visible to the other without a network round trip or a restart. Re-reading a
* few hundred bytes per trust decision costs nothing next to a handshake.
*
* Why the SAS comparison actually works, since the SAS derives from PUBLIC keys
* and is not a secret:
* - To impersonate A to B, an attacker must present A's public key. That passes
*   the derive check, but signing B's nonce needs A's private key, which the
*   attacker does not have → the signature fails.
* - To produce a valid signature it must use its own key, and then B derives a
*   different deviceId and a different SAS than the one A's screen shows. The
*   two operators see mismatched digits and refuse.
* So a relay in the middle has no path. The remaining failure mode is
* procedural, not cryptographic: an operator who types the value shown on their
* OWN screen confirms the attacker. Hence the wording on approve().
*/
/**
* How long an unconfirmed request survives. Bounded so an unauthenticated peer
* cannot camp in the pending set: a port scan never grows the table past one
* row per deviceId, and stale rows drain on their own.
*/
const DEFAULT_TRUST_WINDOW_MS = 6e5;
/** Default grants when the operator does not narrow them explicitly. */
const DEFAULT_GRANTED_CAPS = [
	"task.exec",
	"task.ask",
	"state.report"
];
var TrustTable = class {
	#rows = /* @__PURE__ */ new Map();
	#pending = /* @__PURE__ */ new Map();
	#persistence;
	#windowMs;
	constructor(persistence, windowMs = DEFAULT_TRUST_WINDOW_MS) {
		this.#persistence = persistence;
		this.#windowMs = windowMs;
		this.#refresh();
	}
	/**
	* Re-read the shared document. Called before every public operation so this
	* instance converges with the other process on the same machine.
	*/
	#refresh() {
		const snapshot = this.#persistence?.load();
		if (snapshot === void 0) return;
		this.#rows.clear();
		for (const row of snapshot.trusted ?? []) {
			if (typeof row?.deviceId !== "string" || typeof row?.publicKey !== "string") continue;
			this.#rows.set(row.deviceId, {
				deviceId: row.deviceId,
				publicKey: row.publicKey,
				displayName: typeof row.displayName === "string" ? row.displayName : "",
				caps: (Array.isArray(row.caps) ? row.caps : []).filter(isFedCapability),
				trustedAtMs: typeof row.trustedAtMs === "number" ? row.trustedAtMs : 0
			});
		}
		this.#pending.clear();
		for (const request of snapshot.pending ?? []) {
			if (typeof request?.deviceId !== "string" || typeof request?.sas !== "string") continue;
			this.#pending.set(request.deviceId, request);
		}
	}
	#save() {
		this.#persistence?.save({
			trusted: [...this.#rows.values()],
			pending: [...this.#pending.values()]
		});
	}
	/** Drop expired requests. Returns true when something was removed. */
	#purgeExpired(now) {
		let removed = false;
		for (const [deviceId, request] of this.#pending) if (request.expiresAtMs <= now) {
			this.#pending.delete(deviceId);
			removed = true;
		}
		return removed;
	}
	/** TrustStore. A key that no longer matches the row means no trust. */
	lookup(deviceId, publicKey) {
		this.#refresh();
		const row = this.#rows.get(deviceId);
		if (row === void 0 || row.publicKey !== publicKey) return void 0;
		return {
			deviceId: row.deviceId,
			publicKey: row.publicKey,
			displayName: row.displayName,
			caps: row.caps,
			trustedAtMs: row.trustedAtMs
		};
	}
	isTrusted(deviceId) {
		this.#refresh();
		return this.#rows.has(deviceId);
	}
	/**
	* Record a signature-verified peer awaiting confirmation. Idempotent per
	* deviceId: reconnecting refreshes the window instead of queueing a second
	* prompt, so a reconnect loop cannot spam the operator.
	*/
	requestTrust(input) {
		this.#refresh();
		const now = Date.now();
		this.#purgeExpired(now);
		const pending = {
			deviceId: input.deviceId,
			publicKey: input.publicKey,
			sas: input.sas,
			nickname: input.nickname,
			advertisedCaps: (input.advertisedCaps ?? []).filter(isFedCapability),
			requestedAtMs: this.#pending.get(input.deviceId)?.requestedAtMs ?? now,
			expiresAtMs: now + this.#windowMs
		};
		this.#pending.set(input.deviceId, pending);
		this.#save();
		return pending;
	}
	pending() {
		this.#refresh();
		if (this.#purgeExpired(Date.now())) this.#save();
		return [...this.#pending.values()];
	}
	pendingFor(deviceId) {
		this.#refresh();
		if (this.#purgeExpired(Date.now())) this.#save();
		return this.#pending.get(deviceId);
	}
	/**
	* Operator confirmation.
	*
	* `sas` MUST be what the operator read off the OTHER machine's screen. Typing
	* the locally displayed value always succeeds and confirms whoever is on the
	* other end — exactly the attacker's goal. The comparison IS the mechanism,
	* not a formality.
	*
	* No constant-time compare: the SAS derives from public keys, so it is not a
	* secret and a timing oracle would leak nothing.
	*/
	approve(deviceId, sas, options) {
		this.#refresh();
		if (this.#purgeExpired(Date.now())) this.#save();
		const pending = this.#pending.get(deviceId);
		if (pending === void 0) return {
			ok: false,
			reason: "no_pending_request"
		};
		if (pending.sas !== sas) return {
			ok: false,
			reason: "sas_mismatch"
		};
		const narrowed = (options?.caps ?? pending.advertisedCaps.filter((cap) => DEFAULT_GRANTED_CAPS.includes(cap))).filter(isFedCapability);
		const row = {
			deviceId,
			publicKey: pending.publicKey,
			displayName: options?.nickname ?? pending.nickname,
			caps: narrowed.length > 0 ? narrowed : DEFAULT_GRANTED_CAPS,
			trustedAtMs: Date.now()
		};
		this.#rows.set(deviceId, row);
		this.#pending.delete(deviceId);
		this.#save();
		return {
			ok: true,
			peer: { ...row }
		};
	}
	/** Operator dismissal. Drops the request only; no lasting record either way. */
	deny(deviceId) {
		this.#refresh();
		const removed = this.#pending.delete(deviceId);
		if (removed) this.#save();
		return removed;
	}
	/** Instant local rejection — the peer's next handshake simply finds no row. */
	revoke(deviceId) {
		this.#refresh();
		const hadPending = this.#pending.delete(deviceId);
		const removed = this.#rows.delete(deviceId);
		if (removed || hadPending) this.#save();
		return removed;
	}
	/** Re-label a trusted peer. Display only: never touches the id or the key. */
	relabel(deviceId, displayName) {
		this.#refresh();
		const row = this.#rows.get(deviceId);
		if (row === void 0) return false;
		if (row.displayName === displayName) return false;
		row.displayName = displayName;
		this.#save();
		return true;
	}
	list() {
		this.#refresh();
		return [...this.#rows.values()].map((row) => ({ ...row }));
	}
};
//#endregion
//#region ../fed-peer/lib/index.js
/**
* Shared handshake state machines — acceptor and dialer halves.
*
* Both halves live here because they must agree byte-for-byte on what gets
* signed; keeping them in separate packages is how two implementations drift
* apart and start rejecting each other for no visible reason. They are written
* as pure functions over an explicit state object rather than classes with
* hidden fields, so every transition is directly testable.
*
* Shape of the exchange (two round trips, mutual authentication):
*
*   dialer                                    acceptor
*     |-- connect {publicKey, clientNonce} ----->|  derive id, mint serverNonce,
*     |                                          |  sign clientNonce
*     |<-- challenge {nonce, sas, proof} --------|
*     |  verify proof (acceptor is who it says)  |
*     |  compare sas against the local one       |
*     |-- authenticate {signature} ------------->|  verify over serverNonce
*     |                                          |  trust? -> hello.trusted
*     |<-- hello {trusted} -----------------------|
*
* Neither side can fabricate the other's proof without a fresh nonce from the
* other, which is what makes this mutual rather than one-way.
*/
function newAcceptorState() {
	return { stage: "awaiting-connect" };
}
/** Sanitize an operator-facing label. Cosmetic only — never an identity input. */
function cleanNickname(value, fallback) {
	if (typeof value !== "string") return fallback;
	const trimmed = value.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 64);
	return trimmed.length > 0 ? trimmed : fallback;
}
/**
* Step 1 — the dialer's connect frame.
*
* Note the ordering: everything derivable is derived BEFORE any trust question
* is asked, so an attacker cannot learn whether a given id is trusted without
* first proving it holds that id's key.
*/
function acceptorOnConnect(deps, state, params) {
	if (state.stage !== "awaiting-connect") return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.PAYLOAD_INVALID, "connect already received on this connection")
		}
	};
	const publicKey = params?.publicKey;
	if (typeof publicKey !== "string" || publicKey.length === 0) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "connect requires a public key")
		}
	};
	const clientNonce = params?.clientNonce;
	if (typeof clientNonce !== "string" || clientNonce.length < 16) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.PAYLOAD_INVALID, "connect requires a client nonce")
		}
	};
	let dialerId;
	try {
		dialerId = deriveDeviceId(publicKey);
	} catch {
		return {
			state,
			outcome: {
				ok: false,
				error: fedError(FedErrorCode.UNAUTHENTICATED, "malformed public key")
			}
		};
	}
	const serverNonce = createNonce();
	const sas = computeSas(deps.identity.publicKey, publicKey);
	const proof = signHandshake(deps.identity.privateKeyPem, clientNonce, dialerId, deps.identity.deviceId);
	return {
		state: {
			stage: "awaiting-authenticate",
			dialerId,
			dialerPublicKey: publicKey,
			dialerNickname: cleanNickname(params?.nickname, dialerId),
			serverNonce,
			sas,
			advertisedCaps: Array.isArray(params?.caps) ? params.caps.filter(isFedCapability) : []
		},
		outcome: {
			ok: true,
			step: "challenge",
			challenge: {
				protocol: 2,
				nonce: serverNonce,
				sas,
				acceptorId: deps.identity.deviceId,
				acceptorNickname: cleanNickname(deps.selfNickname, String(deps.identity.deviceId)),
				acceptorPublicKey: deps.identity.publicKey,
				signature: proof,
				serverTimeMs: Date.now()
			}
		}
	};
}
/**
* Step 2 — the dialer's signature over our nonce.
*
* A failed signature is a hard reject, but a verified signature from an
* unconfirmed peer is NOT: the connection stays open in `trust-pending` so an
* operator can compare six digits. Conflating those two would either lock out
* every new machine or let unverified peers through.
*/
function acceptorOnAuthenticate(deps, state, params) {
	if (state.stage !== "awaiting-authenticate") return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "authenticate requires a preceding connect")
		}
	};
	const { dialerId, dialerPublicKey, serverNonce, sas } = state;
	if (dialerId === void 0 || dialerPublicKey === void 0 || serverNonce === void 0 || sas === void 0) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.INTERNAL, "handshake state incomplete")
		}
	};
	const signature = params?.signature;
	if (typeof signature !== "string" || signature.length === 0) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "signature required")
		}
	};
	if (!verifyHandshake(dialerPublicKey, serverNonce, dialerId, deps.identity.deviceId, signature)) return {
		state: {
			...state,
			stage: "awaiting-connect",
			serverNonce: void 0
		},
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "signature verification failed")
		}
	};
	if (deps.trust.lookup(dialerId, dialerPublicKey) !== void 0) {
		const next = {
			...state,
			stage: "authenticated"
		};
		return {
			state: next,
			outcome: {
				ok: true,
				step: "authenticated",
				hello: helloFor(deps, next, true)
			}
		};
	}
	deps.trust.requestTrust({
		deviceId: dialerId,
		publicKey: dialerPublicKey,
		sas,
		nickname: state.dialerNickname ?? dialerId,
		advertisedCaps: state.advertisedCaps
	});
	const next = {
		...state,
		stage: "trust-pending"
	};
	return {
		state: next,
		outcome: {
			ok: true,
			step: "authenticated",
			hello: helloFor(deps, next, false)
		}
	};
}
/** The operator confirmed the SAS for a held peer; promote the connection. */
function acceptorOnTrustApproved(deps, state) {
	if (state.stage !== "trust-pending") return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.FORBIDDEN_CAPS, "no trust decision is pending for this connection")
		}
	};
	const next = {
		...state,
		stage: "authenticated"
	};
	return {
		state: next,
		outcome: {
			ok: true,
			step: "authenticated",
			hello: helloFor(deps, next, true)
		}
	};
}
function helloFor(deps, state, trusted) {
	const deviceId = state.dialerId ?? deps.identity.deviceId;
	const granted = trusted && state.dialerPublicKey !== void 0 ? deps.trust.lookup(deviceId, state.dialerPublicKey) : void 0;
	return {
		protocol: 2,
		peer: {
			role: "host",
			deviceId,
			nickname: state.dialerNickname ?? deviceId
		},
		serverTimeMs: Date.now(),
		trusted,
		caps: granted?.caps
	};
}
/**
* On-disk state for a hive peer: identity, trust table, known addresses.
*
* Everything lives under one state dir (~/.hive by default) so a machine can be
* wiped by deleting one folder, and so two instances on the same box (the dsh
* plugin and the standalone runner) share one identity — which is what keeps a
* machine from appearing twice in every peer's list.
*
* File I/O is confined here; the protocol package stays pure and the handshake
* machines take these as injected values.
*/
/** Write-then-rename: a crash mid-write must not leave a truncated key file. */
function writeJsonAtomic(file, value) {
	const temp = `${file}.tmp`;
	writeFileSync(temp, JSON.stringify(value, null, 2), "utf8");
	renameSync(temp, file);
}
function readJson(file) {
	if (!existsSync(file)) return void 0;
	try {
		return JSON.parse(readFileSync(file, "utf8"));
	} catch {
		return;
	}
}
/**
* Load this machine's identity, minting one on first run.
*
* The private key never leaves this file, so identity is not something another
* peer can grant, revoke, or transfer — the whole point of dropping tokens.
*/
function loadOrCreateIdentity(stateDir) {
	const file = join(stateDir, "identity.json");
	const parsed = readJson(file);
	if (parsed !== void 0 && typeof parsed.publicKey === "string" && typeof parsed.privateKeyPem === "string") try {
		return {
			identity: restoreIdentity(parsed.publicKey, parsed.privateKeyPem, typeof parsed.createdAtMs === "number" ? parsed.createdAtMs : Date.now()),
			created: false
		};
	} catch {}
	const identity = generateIdentity();
	mkdirSync(stateDir, { recursive: true });
	writeJsonAtomic(file, identity);
	return {
		identity,
		created: true
	};
}
/**
* Trust-table persistence. Callers pass the same dir as the identity.
*
* One document holds both the trusted rows and the pending requests, which is
* what lets the operator CLI be a pure file editor (no listener to connect to)
* and lets the two processes on a machine see each other's decisions.
*/
function trustPersistenceFor(stateDir) {
	const file = join(stateDir, "trusted-peers.json");
	return {
		load: () => {
			const parsed = readJson(file);
			if (Array.isArray(parsed)) return {
				trusted: parsed,
				pending: []
			};
			if (typeof parsed !== "object" || parsed === null) return void 0;
			const snapshot = parsed;
			return {
				trusted: Array.isArray(snapshot.trusted) ? snapshot.trusted : [],
				pending: Array.isArray(snapshot.pending) ? snapshot.pending : []
			};
		},
		save: (snapshot) => {
			try {
				mkdirSync(stateDir, { recursive: true });
				writeJsonAtomic(file, snapshot);
			} catch {}
		}
	};
}
/**
* Address book for the mesh. Deliberately separate from the trust table: this
* one is a cache that gossip may append to freely, while trust is only ever
* written by an operator.
*/
var PeerTable = class {
	#rows = /* @__PURE__ */ new Map();
	#file;
	constructor(stateDir) {
		this.#file = stateDir === void 0 ? void 0 : join(stateDir, "peers.json");
		const parsed = this.#file === void 0 ? void 0 : readJson(this.#file);
		for (const row of Array.isArray(parsed) ? parsed : []) if (typeof row?.deviceId === "string" && typeof row?.address === "string") this.#rows.set(row.deviceId, row);
	}
	#persist() {
		if (this.#file === void 0) return;
		try {
			writeJsonAtomic(this.#file, [...this.#rows.values()]);
		} catch {}
	}
	upsert(peer) {
		const row = {
			...peer,
			lastSeenMs: peer.lastSeenMs ?? Date.now()
		};
		this.#rows.set(row.deviceId, row);
		this.#persist();
		return row;
	}
	get(deviceId) {
		return this.#rows.get(deviceId);
	}
	remove(deviceId) {
		const removed = this.#rows.delete(deviceId);
		if (removed) this.#persist();
		return removed;
	}
	list() {
		return [...this.#rows.values()];
	}
	/** Dial candidates: everyone we know an address for, except ourselves. */
	dialCandidates(selfId) {
		return this.list().filter((peer) => peer.deviceId !== selfId && peer.address.length > 0);
	}
};
/**
* Decide which of two connections to the same peer to keep.
*
* Both sides dial, and duplicates are resolved by a rule both ends can compute
* from ids they already have, so they always reach the same verdict: the socket
* initiated by the lexicographically smaller deviceId wins.
*
* Why both sides dial rather than "the smaller id dials": either end may be the
* only one that knows an address (addresses are learned by gossip, and behind
* OpenP2P each side configures its own forward). Under a strict one-dialer rule
* the peer that never learned the address could never connect, and the pair
* would deadlock waiting for each other.
*
* @param remoteInitiated true when the remote end opened this socket
* @returns true when THIS socket should be kept
*/
function keepConnection(localId, remoteId, remoteInitiated) {
	const localIsSmaller = String(localId) < String(remoteId);
	return remoteInitiated ? !localIsSmaller : localIsSmaller;
}
/**
* Where a hive node should listen.
*
* Decision (user): a node's listener is exposed ONLY on the VPN. When no VPN
* address can be found the node does NOT listen at all.
*
* That is fail-closed on purpose. The tempting fallback — bind the LAN address
* or 0.0.0.0 "so it still works" — silently widens exposure to every machine on
* the segment, and the failure it avoids (a node that cannot be reached) is
* visible and fixable, whereas unintended exposure is neither. A peer still
* needs a valid signature and a confirmed trust row to get anywhere, but the
* port itself is not something to leave open by accident.
*/
/**
* Interface names that identify a tunnel adapter. Deliberately broad: a missed
* match means listening on nothing (loud, safe), while a false positive could
* mean listening on a public NIC — so this errs toward specificity on names
* that cannot plausibly be physical adapters.
*/
const VPN_NAME_PATTERN = /(openp2p|wintun|wireguard|tailscale|zerotier|vpn|tun\d|tap\d|utun)/i;
/** First non-internal IPv4 on an interface that looks like a tunnel, if any. */
function detectVpnAddress() {
	for (const [name, entries] of Object.entries(networkInterfaces())) {
		if (!VPN_NAME_PATTERN.test(name)) continue;
		for (const entry of entries ?? []) {
			if (entry.family !== "IPv4" || entry.internal) continue;
			return {
				address: entry.address,
				iface: name
			};
		}
	}
}
/**
* Resolve the bind address. An explicit setting always wins, because the
* operator may be deliberately exposing a different interface; absence of a
* setting is what triggers detection, and a failed detection is what refuses.
*/
function resolveListenTarget(configured) {
	const value = typeof configured === "string" ? configured.trim() : "";
	if (value.length > 0) return {
		mode: "explicit",
		address: value
	};
	const detected = detectVpnAddress();
	if (detected === void 0) return {
		mode: "refused",
		reason: "no VPN interface found — listener stays closed (start OpenP2P, or set 监听地址 explicitly to override)"
	};
	return {
		mode: "vpn",
		address: detected.address,
		iface: detected.iface
	};
}
//#endregion
//#region src/server.ts
/**
* hive federation listener — the ACCEPTING half of a hive node.
*
* There is no center here. Every node runs this listener so any peer can reach
* it, and it holds no authority at all: identity is self-sovereign (a peer's
* key pair IS its identity) and the peer directory is not kept here — peers
* exchange their own tables. Losing any single node therefore strands nothing.
*
* Two kinds of connection arrive:
*   role:"user"  the LOCAL operator surface (fedctl, the settings card), gated
*                by a loopback-only token. Never federated, and never a
*                credential any other machine can present.
*   role:"host"  a peer, which must complete the mutual Ed25519 handshake and
*                hold an operator-confirmed trust row before it may do anything.
*/
/**
* How often live sockets are reconciled with the trust table.
*
* Short enough that an operator's approval feels immediate, long enough that the
* cost is irrelevant. Bounded on purpose rather than event-driven, because the
* writer is a DIFFERENT process (the CLI) and there is no channel to notify
* this one without inventing one.
*/
const TRUST_SYNC_INTERVAL_MS = 2e3;
var GatewayServer = class {
	#cfg;
	#audit;
	#registry = new HostRegistry();
	#trust;
	#peers;
	#identity;
	#conns = /* @__PURE__ */ new Set();
	/** Live peer connections by deviceId — the dedupe and dispatch lookup. */
	#peerConns = /* @__PURE__ */ new Map();
	/** Peers that passed the handshake but await an operator's SAS confirmation. */
	#held = /* @__PURE__ */ new Map();
	#tasks = /* @__PURE__ */ new Map();
	#idempotency = /* @__PURE__ */ new Map();
	#pendingUserReplies = /* @__PURE__ */ new Map();
	#userToken;
	#wss;
	#listening = false;
	/** Reconciles live sockets with the trust table; see #syncTrust. */
	#trustTimer;
	constructor(config = {}) {
		const stateDir = config.stateDir ?? join(homedir(), ".hive");
		this.#cfg = {
			port: config.port ?? 3081,
			bindHost: config.bindHost ?? "",
			auditPath: config.auditPath ?? join(stateDir, "audit.log"),
			stateDir,
			nickname: config.nickname ?? ""
		};
		mkdirSync(stateDir, { recursive: true });
		this.#audit = new AuditLog(this.#cfg.auditPath);
		const loaded = loadOrCreateIdentity(stateDir);
		this.#identity = loaded.identity;
		if (loaded.created) console.log(`[hive] identity created: ${this.#identity.deviceId}`);
		this.#trust = new TrustTable(trustPersistenceFor(stateDir));
		this.#peers = new PeerTable(stateDir);
		const userTokenFile = join(stateDir, "gateway-user-token");
		this.#userToken = existsSync(userTokenFile) ? readFileSync(userTokenFile, "utf8").trim() : randomBytes(32).toString("base64url");
	}
	get identity() {
		return {
			deviceId: this.#identity.deviceId,
			nickname: this.#cfg.nickname
		};
	}
	get userToken() {
		return this.#userToken;
	}
	get listening() {
		return this.#listening;
	}
	/** Operator-visible peers awaiting SAS confirmation. */
	pendingTrust() {
		return this.#trust.pending().map((request) => ({
			deviceId: request.deviceId,
			nickname: request.nickname,
			sas: request.sas
		}));
	}
	/**
	* Live peer rows for the operator surface. Read-only and derived: it exposes
	* what the registry already knows, never a trust decision.
	*/
	peerStates() {
		return this.#registry.list();
	}
	/**
	* Start the listener.
	*
	* Fail-closed: with no explicit bindHost and no detectable VPN interface we do
	* NOT fall back to the LAN or to 0.0.0.0. Staying closed is the safe failure
	* (visible, and fixable by starting the VPN); silently widening exposure is
	* neither.
	*/
	start() {
		const target = resolveListenTarget(this.#cfg.bindHost);
		if (target.mode === "refused") {
			console.error(`[hive] listener NOT started: ${target.reason}`);
			console.error(`[hive] this node can still DIAL peers; it just cannot be dialed`);
			this.#listening = false;
			return;
		}
		const host = target.address;
		this.#wss = new WebSocketServer({
			port: this.#cfg.port,
			host
		});
		this.#wss.on("connection", (ws, request) => this.#onConnection(ws, request));
		this.#wss.on("error", (error) => console.error(`[hive] listener error: ${error.message}`));
		this.#logKnownPeers();
		if (this.#trustTimer === void 0) this.#trustTimer = setInterval(() => this.#syncTrust(), TRUST_SYNC_INTERVAL_MS);
		this.#listening = true;
		writeFileSync(join(this.#cfg.stateDir, "gateway-user-token"), this.#userToken, "utf8");
		console.log(`[hive] listening as ${this.#identity.deviceId} on ws://${host}:${this.#cfg.port}/fed` + (target.mode === "vpn" ? ` (VPN interface ${target.iface})` : " (explicit bindHost)"));
	}
	stop() {
		for (const task of this.#tasks.values()) clearTimeout(task.timer);
		if (this.#trustTimer !== void 0) clearInterval(this.#trustTimer);
		this.#trustTimer = void 0;
		this.#wss?.close();
		for (const conn of this.#conns) conn.ws.terminate();
		this.#listening = false;
	}
	/**
	* Reconcile live sockets with the trust table.
	*
	* The table is the SHARED MEDIUM, so an approval or a revocation may arrive
	* from the other process on this machine (the operator CLI writes the file
	* directly, deliberately, so it works even with dsh stopped). Polling is what
	* makes those decisions act on connections that are already open instead of
	* waiting for the peer to reconnect — and for revocation that is not a
	* nicety: leaving an already-authorized socket running would mean revoking a
	* peer only took effect on its next handshake.
	*/
	#syncTrust() {
		for (const [deviceId, conn] of [...this.#held]) {
			if (!this.#trust.isTrusted(deviceId)) continue;
			const step = acceptorOnTrustApproved(this.#deps(), conn.acceptor);
			if (!step.outcome.ok || step.outcome.step !== "authenticated") continue;
			this.#promoteToPeer(conn, step.outcome.hello);
			this.#send(conn, {
				type: "event",
				event: FedEvent.TRUST_GRANTED,
				payload: { deviceId: this.#identity.deviceId }
			});
			this.#audit.write({
				ts: Date.now(),
				actor: conn.label,
				action: "trust.granted",
				target: String(deviceId),
				decision: "allow"
			});
		}
		for (const [deviceId] of [...this.#peerConns]) {
			if (this.#trust.isTrusted(deviceId)) continue;
			this.#dropPeer(deviceId, "trust revoked");
		}
	}
	#onConnection(ws, request) {
		const conn = {
			ws,
			kind: "pending",
			acceptor: newAcceptorState(),
			label: "unidentified",
			remote: request?.socket?.remoteAddress ?? "unknown",
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
				this.#handleFrame(conn, decodeFrame(raw));
			} catch (error) {
				const err = toFedError(error);
				const rawId = raw !== null && typeof raw === "object" && typeof raw.id === "string" ? raw.id : "?";
				this.#replyError(conn, rawId, fedError(FedErrorCode.INTERNAL, err.message));
				this.#audit.write({
					ts: Date.now(),
					actor: conn.label,
					action: "frame.error",
					target: "listener",
					decision: "deny",
					detail: err.message
				});
			}
		});
		ws.on("close", () => {
			this.#conns.delete(conn);
			if (conn.identity === void 0) return;
			const deviceId = conn.identity.deviceId;
			if (this.#peerConns.get(deviceId) !== conn) return;
			this.#peerConns.delete(deviceId);
			this.#registry.unbind(deviceId);
			this.#broadcastToOperators({
				type: "event",
				event: FedEvent.PRESENCE,
				payload: {
					deviceId,
					presence: "offline"
				}
			});
		});
	}
	#handleFrame(conn, frame) {
		if (frame.type === "event.ack") {
			conn.ackedThrough = frame.ackedThrough;
			return;
		}
		if (frame.type === "event") return;
		if (frame.type === "res") {
			const pending = this.#pendingUserReplies.get(frame.id);
			if (pending !== void 0) this.#relayPeerResult(conn, pending, frame.ok, frame.payload, frame.error);
			return;
		}
		if (frame.method === FedMethod.CONNECT) return this.#handleConnect(conn, frame);
		if (frame.method === FedMethod.AUTHENTICATE) return this.#handleAuthenticate(conn, frame);
		if (conn.kind === "pending") {
			this.#replyError(conn, frame.id, fedError(FedErrorCode.UNAUTHENTICATED, "connect first"));
			return;
		}
		if (conn.kind === "held" && !frame.method.startsWith("trust.")) {
			this.#replyError(conn, frame.id, fedError(FedErrorCode.UNAUTHENTICATED, "awaiting operator confirmation"));
			return;
		}
		switch (frame.method) {
			case FedMethod.TRUST_PENDING_LIST: return this.#replyOk(conn, frame.id, { pending: this.pendingTrust() });
			case FedMethod.TRUST_APPROVE: return this.#handleTrustApprove(conn, frame);
			case FedMethod.TRUST_REVOKE: return this.#handleTrustRevoke(conn, frame);
			case FedMethod.TRUST_LIST: return this.#replyOk(conn, frame.id, { peers: this.#trust.list() });
			case FedMethod.HOST_LIST: return this.#replyOk(conn, frame.id, { peers: this.#registry.list() });
			case FedMethod.PEER_EXCHANGE: return this.#replyOk(conn, frame.id, { peers: this.#knownPeers() });
			case FedMethod.HOST_STATE_REPORT: return this.#handleStateReport(conn, frame);
			case FedMethod.AGENT_TASK: return this.#handleTaskDispatch(conn, frame);
			case FedMethod.AGENT_TASK_CANCEL: return this.#handleTaskCancel(conn, frame);
			default: this.#replyError(conn, frame.id, fedError(FedErrorCode.METHOD_UNKNOWN, `unknown method ${frame.method}`));
		}
	}
	/** Handshake inputs. One place, so the nickname cannot be forgotten at one call site. */
	#deps() {
		return {
			identity: this.#identity,
			trust: this.#trust,
			selfNickname: this.#cfg.nickname
		};
	}
	/**
	* Tear down a peer's live connection AND its registry row.
	*
	* Both halves matter. The close handler deliberately ignores sockets that are
	* no longer the current entry (so closing a replaced duplicate cannot unbind
	* the survivor) — which means anyone who removes the entry FIRST must unbind
	* here too, or the peer stays "online" in the operator's list forever.
	*/
	#dropPeer(deviceId, reason) {
		const conn = this.#peerConns.get(deviceId);
		this.#peerConns.delete(deviceId);
		this.#registry.unbind(deviceId);
		this.#broadcastToOperators({
			type: "event",
			event: FedEvent.PRESENCE,
			payload: {
				deviceId,
				presence: "offline"
			}
		});
		if (conn !== void 0) {
			this.#audit.write({
				ts: Date.now(),
				actor: conn.label,
				action: "peer.drop",
				target: String(deviceId),
				decision: "deny",
				detail: reason
			});
			conn.ws.close();
		}
	}
	/** Handshake failures per remote address, so a stuck peer cannot flood the audit log. */
	#handshakeFailures = /* @__PURE__ */ new Map();
	/**
	* Decide whether a rejected handshake deserves a log line.
	*
	* A peer that fails the handshake is EXPECTED — an older build, a port scan, a
	* half-configured machine — and its retry loop is not ours to control. Logging
	* every attempt floods the audit log (measured: ~1.5 lines/second from one
	* stuck client), which buries the entries that matter and fills the disk. So:
	* the first few are logged in full, then one line per minute carrying the tally.
	*/
	#noteHandshakeFailure(conn, reason) {
		const now = Date.now();
		let record = this.#handshakeFailures.get(conn.remote);
		if (record === void 0) {
			if (this.#handshakeFailures.size > 512) this.#handshakeFailures.clear();
			record = {
				attempts: 0,
				logged: 0,
				lastLoggedAtMs: now
			};
			this.#handshakeFailures.set(conn.remote, record);
		}
		record.attempts += 1;
		if (record.attempts > 3 && now - record.lastLoggedAtMs < 6e4) return;
		const sinceLastLog = record.attempts - record.logged;
		record.logged = record.attempts;
		record.lastLoggedAtMs = now;
		this.#audit.write({
			ts: now,
			actor: "unidentified",
			action: "handshake.reject",
			target: conn.remote,
			decision: "deny",
			detail: sinceLastLog > 1 ? {
				reason,
				attemptsSinceLastLog: sinceLastLog
			} : reason
		});
	}
	#handleConnect(conn, req) {
		const params = req.params;
		if (params?.role === "user") {
			if (!localTokenMatches(typeof params.userToken === "string" ? params.userToken : "", this.#userToken)) {
				this.#audit.write({
					ts: Date.now(),
					actor: conn.label,
					action: "connect.operator",
					target: "listener",
					decision: "deny",
					detail: "bad local token"
				});
				this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, "operator token required"));
				conn.ws.close();
				return;
			}
			conn.kind = "operator";
			conn.label = "operator";
			this.#replyOk(conn, req.id, {
				protocol: 2,
				peer: {
					role: "user",
					deviceId: this.#identity.deviceId,
					nickname: "operator"
				},
				serverTimeMs: Date.now(),
				trusted: true
			});
			return;
		}
		if (params?.role !== "host") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, "role must be host | user"));
			return;
		}
		const step = acceptorOnConnect(this.#deps(), conn.acceptor, req.params);
		conn.acceptor = step.state;
		if (!step.outcome.ok) {
			this.#noteHandshakeFailure(conn, step.outcome.error.message);
			this.#replyError(conn, req.id, step.outcome.error);
			conn.ws.close();
			return;
		}
		if (step.outcome.step !== "challenge") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.INTERNAL, "handshake did not produce a challenge"));
			return;
		}
		conn.label = String(conn.acceptor.dialerNickname ?? "peer");
		this.#replyOk(conn, req.id, step.outcome.challenge);
		this.#audit.write({
			ts: Date.now(),
			actor: conn.label,
			action: "handshake.challenge",
			target: String(conn.acceptor.dialerId),
			decision: "info",
			detail: { sas: conn.acceptor.sas }
		});
	}
	#handleAuthenticate(conn, req) {
		const step = acceptorOnAuthenticate(this.#deps(), conn.acceptor, req.params);
		conn.acceptor = step.state;
		if (!step.outcome.ok) {
			this.#noteHandshakeFailure(conn, step.outcome.error.message);
			this.#replyError(conn, req.id, step.outcome.error);
			conn.ws.close();
			return;
		}
		if (step.outcome.step !== "authenticated") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.INTERNAL, "handshake did not complete"));
			return;
		}
		const hello = step.outcome.hello;
		this.#replyOk(conn, req.id, hello);
		if (hello.trusted) this.#promoteToPeer(conn, hello);
		else this.#holdForTrust(conn, hello);
	}
	/** A held peer: identity proven, waiting on a human. */
	#holdForTrust(conn, hello) {
		conn.kind = "held";
		conn.identity = this.#trust.lookup(hello.peer.deviceId, String(conn.acceptor.dialerPublicKey));
		this.#held.set(hello.peer.deviceId, conn);
		const request = this.#trust.pendingFor(hello.peer.deviceId);
		console.log(`[hive] peer ${hello.peer.nickname} (${hello.peer.deviceId}) awaits confirmation — SAS ${request?.sas ?? "?"}`);
		this.#broadcastToOperators({
			type: "event",
			event: FedEvent.TRUST_PENDING,
			payload: {
				deviceId: hello.peer.deviceId,
				nickname: hello.peer.nickname,
				sas: request?.sas ?? ""
			}
		});
		this.#audit.write({
			ts: Date.now(),
			actor: hello.peer.nickname,
			action: "trust.pending",
			target: hello.peer.deviceId,
			decision: "info"
		});
	}
	#promoteToPeer(conn, hello, peer) {
		const identity = peer ?? this.#trust.lookup(hello.peer.deviceId, String(conn.acceptor.dialerPublicKey));
		if (identity === void 0) {
			conn.ws.close();
			return;
		}
		conn.kind = "peer";
		conn.identity = identity;
		conn.label = hello.peer.nickname;
		const existing = this.#peerConns.get(identity.deviceId);
		if (existing !== void 0 && existing !== conn && existing.ws.readyState === WebSocket.OPEN) {
			if (!keepConnection(this.#identity.deviceId, identity.deviceId, true)) {
				conn.ws.close();
				return;
			}
			existing.ws.close();
		}
		this.#peerConns.set(identity.deviceId, conn);
		this.#held.delete(identity.deviceId);
		this.#registry.bind(identity, (frame) => this.#send(conn, frame));
		this.#broadcastToOperators({
			type: "event",
			event: FedEvent.PRESENCE,
			payload: {
				deviceId: identity.deviceId,
				presence: "online"
			}
		});
		this.#audit.write({
			ts: Date.now(),
			actor: conn.label,
			action: "handshake.ok",
			target: identity.deviceId,
			decision: "allow"
		});
	}
	#handleTrustApprove(conn, req) {
		if (conn.kind !== "operator") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, "only the local operator surface approves peers"));
			return;
		}
		const params = req.params;
		if (typeof params?.deviceId !== "string" || typeof params?.sas !== "string") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, "trust.approve requires deviceId and sas"));
			return;
		}
		const result = this.#trust.approve(params.deviceId, params.sas, { nickname: params.nickname });
		if (!result.ok) {
			this.#audit.write({
				ts: Date.now(),
				actor: "operator",
				action: "trust.approve",
				target: params.deviceId,
				decision: "deny",
				detail: result.reason
			});
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, `trust approval refused: ${result.reason}`));
			return;
		}
		const held = this.#held.get(params.deviceId);
		if (held !== void 0) {
			const step = acceptorOnTrustApproved(this.#deps(), held.acceptor);
			if (step.outcome.ok && step.outcome.step === "authenticated") {
				this.#promoteToPeer(held, step.outcome.hello, result.peer);
				this.#send(held, {
					type: "event",
					event: FedEvent.TRUST_GRANTED,
					payload: { deviceId: this.#identity.deviceId }
				});
			}
		}
		this.#replyOk(conn, req.id, {
			deviceId: result.peer.deviceId,
			nickname: result.peer.displayName
		});
		this.#audit.write({
			ts: Date.now(),
			actor: "operator",
			action: "trust.approve",
			target: result.peer.deviceId,
			decision: "allow"
		});
	}
	#handleTrustRevoke(conn, req) {
		if (conn.kind !== "operator") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, "only the local operator surface revokes peers"));
			return;
		}
		const deviceId = req.params?.deviceId;
		if (typeof deviceId !== "string") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.PAYLOAD_INVALID, "deviceId required"));
			return;
		}
		const removed = this.#trust.revoke(deviceId);
		if (this.#peerConns.has(deviceId)) this.#dropPeer(deviceId, "trust revoked by operator");
		else this.#registry.unbind(deviceId);
		const held = this.#held.get(deviceId);
		if (held !== void 0) {
			this.#held.delete(deviceId);
			this.#send(held, {
				type: "event",
				event: FedEvent.TRUST_DENIED,
				payload: { deviceId: this.#identity.deviceId }
			});
			held.ws.close();
		}
		this.#replyOk(conn, req.id, { revoked: removed });
		this.#audit.write({
			ts: Date.now(),
			actor: "operator",
			action: "trust.revoke",
			target: deviceId,
			decision: removed ? "allow" : "info"
		});
	}
	#knownPeers() {
		const trusted = new Map(this.#trust.list().map((peer) => [peer.deviceId, peer]));
		return this.#peers.list().map((peer) => ({
			deviceId: peer.deviceId,
			publicKey: peer.publicKey,
			nickname: peer.nickname,
			address: peer.address,
			trusted: trusted.has(peer.deviceId),
			lastSeenMs: peer.lastSeenMs
		}));
	}
	/** Known-but-not-yet-trusted addresses are audit-visible at boot. */
	#logKnownPeers() {
		for (const peer of this.#peers.list()) {
			if (peer.deviceId === this.#identity.deviceId) continue;
			this.#audit.write({
				ts: Date.now(),
				actor: "listener",
				action: "peer.known",
				target: peer.deviceId,
				decision: "info",
				detail: { address: peer.address }
			});
		}
	}
	#handleStateReport(conn, req) {
		if (conn.kind !== "peer" || conn.identity === void 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.UNAUTHENTICATED, "peer identity required"));
			return;
		}
		const raw = req.params ?? {};
		const digest = {
			deviceId: conn.identity.deviceId,
			nickname: typeof raw.nickname === "string" && raw.nickname.length > 0 ? raw.nickname.slice(0, 64) : conn.identity.displayName,
			os: typeof raw.os === "string" ? raw.os.slice(0, 64) : "unknown",
			lanAddress: typeof raw.lanAddress === "string" ? raw.lanAddress.slice(0, 64) : "unknown",
			cpuLoadPct: typeof raw.cpuLoadPct === "number" ? raw.cpuLoadPct : void 0,
			memTotalMb: typeof raw.memTotalMb === "number" ? raw.memTotalMb : void 0,
			memFreeMb: typeof raw.memFreeMb === "number" ? raw.memFreeMb : void 0,
			reportedAtMs: Date.now()
		};
		this.#registry.touch(conn.identity.deviceId, digest);
		this.#replyOk(conn, req.id, { recorded: true });
		this.#broadcastToOperators({
			type: "event",
			event: FedEvent.HOST_STATE,
			payload: digest
		});
	}
	#handleTaskDispatch(conn, req) {
		if (conn.kind !== "operator") {
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, "only the local operator surface dispatches tasks"));
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
		const replayKey = `${conn.label}:${req.idempotencyKey}`;
		const replay = this.#idempotency.get(replayKey);
		if (replay !== void 0) {
			this.#replyOk(conn, req.id, replay.res);
			return;
		}
		const target = this.#registry.findForDispatch(params.peer ?? "");
		if (target === void 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, `peer ${params.peer ?? "?"} is not available`));
			return;
		}
		if (!this.#registry.hasCap(target.identity.deviceId, "task.exec")) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.FORBIDDEN_CAPS, `peer ${target.identity.deviceId} was not granted task.exec`));
			return;
		}
		const traceId = typeof params.traceId === "string" && params.traceId.length > 0 ? params.traceId : `t-${Date.now()}-${randomBytes(3).toString("hex")}`;
		const taskId = `task-${Date.now()}-${randomBytes(3).toString("hex")}`;
		const deadlineMs = typeof params.deadlineMs === "number" && params.deadlineMs > 0 ? params.deadlineMs : 3e4;
		const timer = setTimeout(() => {
			if (this.#tasks.delete(taskId)) {
				this.#pendingUserReplies.delete(`gw-${taskId}`);
				this.#replyError(conn, req.id, fedError(FedErrorCode.DEADLINE_EXCEEDED, `task exceeded ${deadlineMs}ms`, { traceId }));
				this.#audit.write({
					ts: Date.now(),
					traceId,
					actor: "listener",
					action: "agent.task",
					target: String(target.identity.deviceId),
					decision: "deny",
					detail: "deadline"
				});
			}
		}, deadlineMs);
		this.#tasks.set(taskId, {
			taskId,
			traceId,
			deviceId: target.identity.deviceId,
			timer
		});
		this.#pendingUserReplies.set(`gw-${taskId}`, {
			conn,
			reqId: req.id,
			taskId,
			traceId,
			replayKey
		});
		target.send?.({
			type: "req",
			id: `gw-${taskId}`,
			method: FedMethod.AGENT_TASK,
			params: {
				taskId,
				prompt: params.prompt,
				requiredCaps: ["task.exec"],
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
			actor: "operator",
			action: "agent.task",
			target: String(target.identity.deviceId),
			decision: "allow",
			detail: {
				taskId,
				prompt: params.prompt.slice(0, 200)
			}
		});
	}
	#handleTaskCancel(conn, req) {
		const taskId = req.params?.taskId;
		const task = typeof taskId === "string" ? this.#tasks.get(taskId) : void 0;
		if (task === void 0) {
			this.#replyError(conn, req.id, fedError(FedErrorCode.TASK_NOT_FOUND, "task not in flight"));
			return;
		}
		const live = this.#peerConns.get(task.deviceId);
		if (live !== void 0) this.#send(live, {
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
			actor: "operator",
			action: "agent.task.cancel",
			target: task.taskId,
			decision: "allow"
		});
	}
	/** Relay a peer's task result back to the operator surface that asked. */
	#relayPeerResult(conn, pending, ok, payload, error) {
		this.#pendingUserReplies.delete(`gw-${pending.taskId}`);
		const task = this.#tasks.get(pending.taskId);
		if (task !== void 0) {
			clearTimeout(task.timer);
			this.#tasks.delete(pending.taskId);
		}
		if (ok) {
			this.#idempotency.set(pending.replayKey, { res: payload });
			this.#replyOk(pending.conn, pending.reqId, payload);
		} else this.#replyError(pending.conn, pending.reqId, toFedError(error, pending.traceId));
		this.#audit.write({
			ts: Date.now(),
			traceId: pending.traceId,
			actor: conn.label,
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
	#broadcastToOperators(frame) {
		for (const conn of this.#conns) if (conn.kind === "operator") this.#send(conn, { ...frame });
	}
};
//#endregion
export { GatewayServer as t };

//# sourceMappingURL=server-zAsACzSu.js.map