import { FedErrorCode, MAX_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, computeSas, createNonce, deriveDeviceId, fedError, generateIdentity, isFedCapability, restoreIdentity, signHandshake, verifyHandshake } from "../../fed-protocol/lib/host/index.js";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { networkInterfaces } from "node:os";
export * from "../../fed-protocol/lib/host/index.js";
//#region src/handshake.ts
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
				protocol: PROTOCOL_VERSION,
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
		protocol: PROTOCOL_VERSION,
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
				min: MIN_PROTOCOL_VERSION,
				max: MAX_PROTOCOL_VERSION
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
//#endregion
//#region src/stores.ts
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
//#endregion
//#region src/network.ts
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
export { PeerTable, acceptorOnAuthenticate, acceptorOnConnect, acceptorOnTrustApproved, detectVpnAddress, dialerBuildConnect, dialerOnChallenge, dialerOnHello, keepConnection, loadOrCreateIdentity, newAcceptorState, newDialerState, resolveListenTarget, trustPersistenceFor };

//# sourceMappingURL=index.js.map