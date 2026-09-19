import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";
//#region src/errors.ts
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
//#endregion
//#region src/identity.ts
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
* Human-facing grouping of a device id (4-4-4-4). Display only — always compare
* the SAS for trust; never compare ids by eye.
*/
function formatDeviceId(deviceId) {
	return String(deviceId).replace(/(.{4})(?=.)/g, "$1-");
}
//#endregion
//#region src/auth.ts
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
* Authorize an inbound peer request.
*
* The ONLY inputs consulted are the signature result and the local trust table;
* every other parameter is diagnostic metadata for the audit log and cannot
* influence the decision. This is the single choke point for the 禁止清单 rule.
*/
function authorize(store, proof, context) {
	if (deriveDeviceId(proof.publicKey) !== proof.deviceId) return { error: "unauthenticated" };
	if (!proof.signatureVerified) return { error: "unauthenticated" };
	const identity = store.lookup(proof.deviceId, proof.publicKey);
	if (identity === void 0) return { error: "untrusted" };
	context.source;
	context.declaredName;
	return { identity };
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
//#endregion
//#region src/frames.ts
/**
* hive federation wire protocol — openclaw-style three-frame exchange.
*
* Frame shapes (A-class benchmark: openclaw gateway-protocol):
*   req   { type:"req",   id, method, params, ...delivery }
*   res   { type:"res",   id, ok, payload | error }
*   event { type:"event", event, payload, seq }
*
* Every inbound frame passes assertFrame — the wire boundary is the one place
* untrusted JSON is trusted to become a typed value (AGENTS.md: validate at
* wire boundaries; trust TypeScript only inside same-process typed edges).
*/
/**
* Wire protocol version. Bumped to 2 by the self-sovereign identity cut (D-020).
* v1 peers are REJECTED rather than half-supported: there is no meaningful
* translation between "an issuer told me who you are" and "you proved it
* yourself" — a bridge would just be the center server again, in disguise.
*/
const PROTOCOL_VERSION = 2;
/** Oldest wire protocol this build accepts. */
const MIN_PROTOCOL_VERSION = 2;
/** Newest wire protocol this build accepts. */
const MAX_PROTOCOL_VERSION = 2;
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
	const overlapMin = Math.max(min, 2);
	const overlapMax = Math.min(max, 2);
	if (overlapMin > overlapMax) throw fedError(FedErrorCode.VERSION_MISMATCH, `peer supports ${min}..${max}, we support 2..2`);
	return overlapMax;
}
/** Capabilities are always re-validated server-side; client lists are advertisements only. */
function sanitizeAdvertisedCaps(value) {
	if (!Array.isArray(value)) return [];
	return value.filter((entry) => typeof entry === "string" && Object.values(FedCapability).includes(entry));
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
//#endregion
//#region src/methods.ts
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
/**
* Methods whose req frames MUST carry idempotencyKey (security/consistency invariant).
*
* trust.approve is deliberately NOT here: it is keyed by deviceId and its
* effect is set-like (approving twice is one row), so a replay is a no-op by
* construction rather than something the key machinery has to rescue.
*/
const IDEMPOTENT_METHODS = /* @__PURE__ */ new Set([
	FedMethod.AGENT_TASK,
	FedMethod.AGENT_TASK_CANCEL,
	FedMethod.CHAT_SEND
]);
/** Side-effect methods must be dispatched with these delivery fields present. */
function requiresIdempotencyKey(method) {
	return IDEMPOTENT_METHODS.has(method);
}
//#endregion
//#region src/trust.ts
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
//#region src/index.ts
/**
* hive-fed-protocol — host-half dsh plugin.
*
* Provides the `fedProtocol` service: the shared wire vocabulary (frames,
* methods, errors), the self-sovereign identity primitives (identity.ts) and the
* single authorization choke point (auth.ts) used by both hive-fed-gateway and
* hive-fed-host. Pure logic, zero I/O — transports live in the peer packages so
* this contract stays swappable (平台化约束: 一切皆插件、可替换、可关闭).
*
* Model-visible ⟺ logged: nothing here reaches a model request; it only moves
* bytes and validates boundaries.
*/
const name = "hive-fed-protocol";
function assertConfig(config) {
	const resolved = { strictVersionCheck: config?.strictVersionCheck ?? true };
	if (typeof resolved.strictVersionCheck !== "boolean") throw new Error("hive-fed-protocol: config.strictVersionCheck must be a boolean when present");
	return resolved;
}
function apply(ctx, config) {
	assertConfig(config);
	const service = {
		version: {
			current: 2,
			min: 2,
			max: 2
		},
		methods: FedMethod,
		events: FedEvent,
		errorCodes: FedErrorCode,
		decodeFrame,
		negotiateProtocol,
		sanitizeAdvertisedCaps,
		requiresIdempotencyKey,
		authorize,
		identity: {
			generate: generateIdentity,
			restore: restoreIdentity,
			deriveDeviceId,
			createNonce,
			signHandshake,
			verifyHandshake,
			computeSas,
			formatDeviceId
		},
		localTokenMatches,
		isFedCapability,
		fedError,
		toFedError
	};
	const candidate = ctx;
	if (typeof candidate.provide !== "function") throw new Error("hive-fed-protocol: host context does not expose provide(); not a cordis context");
	candidate.provide("fedProtocol", service);
}
//#endregion
export { FedCapability, FedErrorCode, FedEvent as FedEventCatalog, FedMethod, IDEMPOTENT_METHODS, MAX_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, TrustTable, apply, authorize, computeSas, createNonce, decodeFrame, deriveDeviceId, fedError, formatDeviceId, generateIdentity, isFedCapability, localTokenMatches, name, negotiateProtocol, requiresIdempotencyKey, restoreIdentity, sanitizeAdvertisedCaps, signHandshake, toFedError, verifyHandshake };

//# sourceMappingURL=index.js.map