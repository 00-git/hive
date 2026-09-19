import { AuditLog } from "./audit.js";
import { runOp } from "./ops.js";
import { WebSocket } from "ws";
import { freemem, homedir, hostname, platform, totalmem, uptime } from "node:os";
import { join } from "node:path";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
/** Sanitize an operator-facing label. Cosmetic only — never an identity input. */
function cleanNickname(value, fallback) {
	if (typeof value !== "string") return fallback;
	const trimmed = value.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 64);
	return trimmed.length > 0 ? trimmed : fallback;
}
function newDialerState() {
	return { stage: "idle" };
}
/** Build the connect frame. Always the first thing a dialer sends. */
function dialerBuildConnect(deps, state, options) {
	const clientNonce = createNonce();
	return {
		state: {
			...state,
			stage: "awaiting-challenge",
			clientNonce
		},
		params: {
			role: "host",
			protocol: {
				min: 2,
				max: 2
			},
			publicKey: deps.identity.publicKey,
			clientNonce,
			nickname: options?.nickname ?? "",
			caps: options?.caps ?? []
		}
	};
}
/**
* Verify the acceptor's challenge.
*
* Three independent checks, all fatal: the id must derive from the presented
* key, the proof must verify over OUR nonce, and the claimed SAS must equal the
* one we compute locally. The last one is what a person then re-checks out of
* band — if the acceptor is an impostor, its key differs and so does the SAS.
*/
function dialerOnChallenge(deps, state, challenge) {
	if (state.stage !== "awaiting-challenge" || state.clientNonce === void 0) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "challenge without a preceding connect")
		}
	};
	if (challenge === void 0) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.PAYLOAD_INVALID, "challenge payload missing")
		}
	};
	let derived;
	try {
		derived = deriveDeviceId(challenge.acceptorPublicKey);
	} catch {
		return {
			state,
			outcome: {
				ok: false,
				error: fedError(FedErrorCode.UNAUTHENTICATED, "acceptor sent a malformed key")
			}
		};
	}
	if (derived !== challenge.acceptorId) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "acceptor id does not match its key")
		}
	};
	if (!verifyHandshake(challenge.acceptorPublicKey, state.clientNonce, deps.identity.deviceId, derived, challenge.signature)) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "acceptor proof did not verify")
		}
	};
	const sas = computeSas(deps.identity.publicKey, challenge.acceptorPublicKey);
	if (sas !== challenge.sas) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "sas mismatch: the two ends disagree on the keys in play")
		}
	};
	return {
		state: {
			...state,
			stage: "awaiting-hello",
			acceptorId: derived,
			acceptorPublicKey: challenge.acceptorPublicKey,
			acceptorNickname: cleanNickname(challenge.acceptorNickname, String(derived)),
			sas
		},
		outcome: {
			ok: true,
			step: "authenticate",
			params: { signature: signHandshake(deps.identity.privateKeyPem, challenge.nonce, deps.identity.deviceId, derived) }
		}
	};
}
/**
* Fold the acceptor's hello in, and decide for OURSELVES whether the acceptor is
* trusted. `hello.trusted` describes the acceptor's opinion of us and must never
* be reused as our opinion of them — that inversion is the classic mutual-auth
* bug, and it is why the dialer consults its own table here.
*/
function dialerOnHello(deps, state, hello) {
	if (state.stage !== "awaiting-hello" || state.acceptorId === void 0 || state.acceptorPublicKey === void 0 || state.sas === void 0) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "hello without a preceding challenge")
		}
	};
	if (hello?.peer === void 0 || typeof hello.peer.deviceId !== "string") return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.PAYLOAD_INVALID, "hello payload missing a peer")
		}
	};
	if (hello.peer.deviceId !== deps.identity.deviceId) return {
		state,
		outcome: {
			ok: false,
			error: fedError(FedErrorCode.UNAUTHENTICATED, "hello describes an unexpected peer")
		}
	};
	const mine = deps.trust.lookup(state.acceptorId, state.acceptorPublicKey);
	if (mine === void 0) deps.trust.requestTrust({
		deviceId: state.acceptorId,
		publicKey: state.acceptorPublicKey,
		sas: state.sas,
		nickname: state.acceptorNickname ?? String(state.acceptorId),
		advertisedCaps: hello.caps
	});
	else deps.trust.relabel(state.acceptorId, state.acceptorNickname ?? String(state.acceptorId));
	return {
		state: {
			...state,
			stage: "ready"
		},
		outcome: {
			ok: true,
			step: "ready",
			trusted: mine !== void 0,
			peerTrustsUs: hello.trusted === true,
			nickname: state.acceptorNickname ?? String(state.acceptorId)
		}
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
//#endregion
//#region src/client.ts
/**
* hive federation dialer — the OUTBOUND half of a hive node.
*
* A node dials every peer it knows and also listens (see the gateway half), so
* the pair survives either side having the reachable address. Nothing here is
* privileged: reaching a peer's port is not access, and an untouched trust row
* is not trust.
*
* Trust is established per machine and confirmed by a human: the handshake
* proves WHICH key is on the other end, and the operator decides whether that
* key is acceptable by comparing six digits with the other machine's screen.
*/
/**
* How often links are re-checked against the trust table.
*
* The operator CLI approves by writing the shared file from another process, so
* there is no callback on this side to hang the promotion off. Two seconds is
* short enough that a confirmation feels immediate.
*/
const TRUST_SYNC_INTERVAL_MS = 2e3;
var HostClient = class {
	#cfg;
	#audit;
	#identity;
	#trust;
	#peers;
	#links = /* @__PURE__ */ new Map();
	#pending = /* @__PURE__ */ new Map();
	#stateTimer;
	/** Promotes links once both operators have confirmed; see #syncTrust. */
	#trustTimer;
	#closedByUs = false;
	constructor(config = {}) {
		const stateDir = config.stateDir ?? join(homedir(), ".hive");
		this.#cfg = {
			peerUrls: (config.peerUrls ?? []).filter((url) => url.length > 0),
			nickname: config.nickname ?? hostname(),
			stateDir,
			whitelistDirs: config.whitelistDirs ?? [process.cwd()],
			stateIntervalMs: config.stateIntervalMs ?? 15e3
		};
		this.#audit = new AuditLog(join(stateDir, "host-audit.log"));
		const loaded = loadOrCreateIdentity(stateDir);
		this.#identity = loaded.identity;
		this.#trust = new TrustTable(trustPersistenceFor(stateDir));
		this.#peers = new PeerTable(stateDir);
		if (loaded.created) console.log(`[hive-fed-host] identity created: ${this.#identity.deviceId}`);
	}
	/** This node's own id — the value every peer will key its trust row off. */
	get deviceId() {
		return this.#identity.deviceId;
	}
	/** Peers awaiting THIS machine's operator confirmation (the outbound half). */
	pendingTrust() {
		return this.#trust.pending().map((request) => ({
			deviceId: request.deviceId,
			nickname: request.nickname,
			sas: request.sas
		}));
	}
	start() {
		for (const url of this.#cfg.peerUrls) this.#dial(url);
		for (const peer of this.#peers.dialCandidates(this.#identity.deviceId)) if (peer.address.startsWith("ws://") || peer.address.startsWith("wss://")) this.#dial(peer.address);
		if (this.#stateTimer === void 0) this.#stateTimer = setInterval(() => this.#reportState(), this.#cfg.stateIntervalMs);
		if (this.#trustTimer === void 0) this.#trustTimer = setInterval(() => this.#syncTrust(), TRUST_SYNC_INTERVAL_MS);
	}
	stop() {
		this.#closedByUs = true;
		if (this.#stateTimer !== void 0) clearInterval(this.#stateTimer);
		this.#stateTimer = void 0;
		if (this.#trustTimer !== void 0) clearInterval(this.#trustTimer);
		this.#trustTimer = void 0;
		for (const link of this.#links.values()) link.ws.close();
		this.#links.clear();
	}
	/**
	* Promote links that have BOTH confirmations.
	*
	* The operator CLI writes the trust file from another process, so this side
	* has no callback to hang the promotion off. Polling is the honest answer:
	* the file is the shared medium, and a link becomes usable the moment both
	* machines' operators have confirmed — not a heartbeat later than needed.
	*/
	#syncTrust() {
		for (const link of this.#links.values()) {
			if (link.ready || link.peerId === void 0 || !link.peerTrustsUs) continue;
			if (link.dialer.stage !== "ready") continue;
			if (!this.#trust.isTrusted(link.peerId)) continue;
			link.ready = true;
			this.#trust.relabel(link.peerId, link.nickname);
			console.log(`[hive-fed-host] ${link.nickname} 双向确认完成，联邦链路已可用`);
			this.#audit.write({
				ts: Date.now(),
				actor: this.#cfg.nickname,
				action: "trust.granted",
				target: String(link.peerId),
				decision: "allow"
			});
			this.#reportState();
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
	#dial(url) {
		if (this.#links.has(url)) return;
		const ws = new WebSocket(url);
		const link = {
			url,
			ws,
			dialer: newDialerState(),
			nickname: url,
			ready: false,
			peerTrustsUs: false,
			attempt: 0
		};
		this.#links.set(url, link);
		ws.on("open", () => {
			link.attempt = 0;
			const built = dialerBuildConnect(this.#deps(), link.dialer, {
				nickname: this.#cfg.nickname,
				caps: [
					"task.exec",
					"task.ask",
					"state.report"
				]
			});
			link.dialer = built.state;
			this.#send(ws, "hs-connect", FedMethod.CONNECT, built.params);
		});
		ws.on("message", (data) => {
			let frame;
			try {
				frame = decodeFrame(JSON.parse(String(data)));
			} catch (error) {
				this.#audit.write({
					ts: Date.now(),
					actor: link.url,
					action: "frame.invalid",
					target: "host",
					decision: "deny",
					detail: String(error)
				});
				return;
			}
			try {
				if (frame.type === "req") {
					this.#handleRequest(ws, frame);
					return;
				}
				if (frame.type === "res") {
					this.#handleResponse(link, frame.id, frame.ok, frame.payload, frame.error);
					return;
				}
				if (frame.type === "event") this.#handleEvent(link, frame.event, frame.payload);
			} catch (error) {
				console.error(`[hive-fed-host] frame handler failed: ${error instanceof Error ? error.message : String(error)}`);
			}
		});
		ws.on("close", () => {
			this.#links.delete(url);
			link.ready = false;
			for (const [id, pending] of this.#pending) {
				pending.reject(/* @__PURE__ */ new Error("connection closed"));
				this.#pending.delete(id);
			}
			if (this.#closedByUs) return;
			const delay = Math.min(3e4, 1e3 * 2 ** link.attempt) + Math.floor(Math.random() * 250);
			link.attempt += 1;
			console.log(`[hive-fed-host] ${url} disconnected; redialing in ${delay}ms (attempt ${link.attempt})`);
			setTimeout(() => this.#dial(url), delay);
		});
		ws.on("error", (error) => {});
	}
	#send(ws, id, method, params, extra) {
		if (ws.readyState !== WebSocket.OPEN) return;
		ws.send(JSON.stringify({
			type: "req",
			id,
			method,
			params,
			...extra,
			traceId: `host-${Date.now()}`
		}));
	}
	#handleResponse(link, id, ok, payload, error) {
		if (id === "hs-connect") {
			if (!ok) {
				this.#failHandshake(link, error);
				return;
			}
			const step = dialerOnChallenge(this.#deps(), link.dialer, payload);
			link.dialer = step.state;
			if (!step.outcome.ok || step.outcome.step !== "authenticate") {
				this.#failHandshake(link, step.outcome.ok ? /* @__PURE__ */ new Error("peer answered with an unexpected step") : step.outcome.error);
				return;
			}
			this.#send(link.ws, "hs-auth", FedMethod.AUTHENTICATE, step.outcome.params);
			return;
		}
		if (id === "hs-auth") {
			if (!ok) {
				this.#failHandshake(link, error);
				return;
			}
			const step = dialerOnHello(this.#deps(), link.dialer, payload);
			link.dialer = step.state;
			if (!step.outcome.ok || step.outcome.step !== "ready") {
				this.#failHandshake(link, step.outcome.ok ? /* @__PURE__ */ new Error("peer answered with an unexpected step") : step.outcome.error);
				return;
			}
			link.peerId = link.dialer.acceptorId;
			link.nickname = step.outcome.nickname;
			link.peerTrustsUs = step.outcome.peerTrustsUs;
			link.ready = step.outcome.trusted && step.outcome.peerTrustsUs;
			if (link.peerId !== void 0) this.#peers.upsert({
				deviceId: link.peerId,
				publicKey: String(link.dialer.acceptorPublicKey),
				nickname: link.nickname,
				address: link.url,
				trusted: link.ready
			});
			if (link.ready) {
				console.log(`[hive-fed-host] connected to ${link.nickname} (${String(link.peerId)})`);
				this.#audit.write({
					ts: Date.now(),
					actor: this.#cfg.nickname,
					action: "handshake.ok",
					target: String(link.peerId),
					decision: "allow"
				});
				this.#reportState();
			} else {
				const sas = this.#trust.pendingFor(link.peerId)?.sas ?? link.dialer.sas ?? "?";
				console.log(`[hive-fed-host] ${link.nickname} (${String(link.peerId)}) needs confirmation on THIS machine — SAS ${sas}`);
				this.#audit.write({
					ts: Date.now(),
					actor: this.#cfg.nickname,
					action: "trust.pending",
					target: String(link.peerId),
					decision: "info",
					detail: { sas }
				});
			}
			return;
		}
		const pending = this.#pending.get(id);
		if (pending !== void 0) {
			this.#pending.delete(id);
			if (ok) pending.resolve(payload);
			else pending.reject(error);
		}
	}
	#failHandshake(link, error) {
		const message = error instanceof Error ? error.message : JSON.stringify(error);
		console.error(`[hive-fed-host] handshake with ${link.url} rejected: ${message}`);
		this.#audit.write({
			ts: Date.now(),
			actor: this.#cfg.nickname,
			action: "handshake",
			target: link.url,
			decision: "deny",
			detail: message
		});
		this.#links.delete(link.url);
		link.ws.close();
	}
	#handleEvent(link, event, payload) {
		if (event === "trust/granted") {
			link.peerTrustsUs = true;
			if (this.#trust.isTrusted(link.peerId)) link.ready = true;
			console.log(`[hive-fed-host] ${link.nickname} 已确认本机；${link.ready ? "链路已可用" : "本机还需确认对端"}`);
			this.#audit.write({
				ts: Date.now(),
				actor: this.#cfg.nickname,
				action: "trust.granted",
				target: String(link.peerId),
				decision: "allow"
			});
			this.#reportState();
			return;
		}
	}
	#reportState() {
		const digest = {
			nickname: this.#cfg.nickname,
			os: `${platform()} ${hostname()}`,
			lanAddress: "vpn",
			memTotalMb: Math.round(totalmem() / 1024 / 1024),
			memFreeMb: Math.round(freemem() / 1024 / 1024),
			uptimeSec: Math.floor(uptime())
		};
		for (const link of this.#links.values()) if (link.ready) this.#send(link.ws, `state-${Date.now()}`, FedMethod.HOST_STATE_REPORT, digest);
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
				const parsed = JSON.parse(typeof params.prompt === "string" ? params.prompt : "");
				if (parsed === null || typeof parsed !== "object" || typeof parsed.op !== "string") throw new Error("prompt must be a JSON object with an op field");
				const op = parsed.op;
				const args = { ...parsed };
				delete args.op;
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
				actor: "federation",
				action: "task.cancel",
				target: String(req.params?.taskId ?? ""),
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
		if (ws.readyState !== WebSocket.OPEN) return;
		ws.send(JSON.stringify({
			type: "res",
			id,
			ok,
			...ok ? { payload } : { error }
		}));
	}
};
//#endregion
export { HostClient as t };

//# sourceMappingURL=client-BmPB8yBL.js.map