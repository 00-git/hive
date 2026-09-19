//#region src/registry.ts
var HostRegistry = class {
	#hosts = /* @__PURE__ */ new Map();
	/** Attach or re-attach a live connection for an authorized peer. */
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
	/** Rows for peers we have heard from; offline rows included, marked by `online`. */
	list() {
		const rows = [];
		for (const [deviceId, state] of this.#hosts) rows.push({
			...state.digest ?? {
				deviceId,
				nickname: state.identity.displayName,
				os: "unknown",
				lanAddress: "unknown",
				reportedAtMs: state.lastSeenMs
			},
			online: state.send !== void 0
		});
		return rows;
	}
	/**
	* Resolve a dispatch target by device id, the peer's own nickname, or the
	* operator's label for it.
	*
	* Name matching is a convenience lookup ONLY: the request runs against the
	* deviceId resolved here, and capabilities are read from the identity that was
	* authorized at handshake time — never from the name somebody typed. That is
	* what stops a peer from granting itself rights by renaming to match a target.
	*/
	findForDispatch(nameOrId) {
		if (nameOrId.length === 0) return void 0;
		const direct = this.#hosts.get(nameOrId);
		if (direct !== void 0 && direct.send !== void 0) return direct;
		for (const state of this.#hosts.values()) {
			if (state.send === void 0) continue;
			if (state.identity.displayName === nameOrId) return state;
			if (state.digest?.nickname === nameOrId) return state;
		}
	}
	/** Capabilities come from the authorized identity, never from the wire. */
	hasCap(deviceId, cap) {
		return this.#hosts.get(deviceId)?.identity.caps.includes(cap) ?? false;
	}
	isOnline(deviceId) {
		return this.#hosts.get(deviceId)?.send !== void 0;
	}
};
//#endregion
export { HostRegistry };

//# sourceMappingURL=registry.js.map