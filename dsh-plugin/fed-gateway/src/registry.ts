/**
 * Live peer registry (acceptor side).
 *
 * Identity and authorization live in the shared TrustTable, so this class holds
 * NO credentials and makes NO trust decisions — it only answers "which
 * authorized peers currently hold a connection, and what did they last report".
 * Keeping those apart is what makes revocation instant: deleting a trust row is
 * enough, with no token store left to purge.
 */
import type { DeviceId, FedCapability, HostStateDigest, PeerIdentity } from '../../fed-peer/lib/index.js'

export interface HostConnectionState {
  identity: PeerIdentity
  /** Live dispatch channel; undefined while the peer is mid-reconnect. */
  send: ((frame: unknown) => void) | undefined
  lastSeenMs: number
  digest: HostStateDigest | undefined
}

export class HostRegistry {
  readonly #hosts = new Map<DeviceId, HostConnectionState>()

  /** Attach or re-attach a live connection for an authorized peer. */
  bind(identity: PeerIdentity, send: (frame: unknown) => void): void {
    this.#hosts.set(identity.deviceId, {
      identity,
      send,
      lastSeenMs: Date.now(),
      digest: this.#hosts.get(identity.deviceId)?.digest,
    })
  }

  unbind(deviceId: DeviceId): void {
    const state = this.#hosts.get(deviceId)
    // Keep the row so the last digest survives a reconnect blip; only the
    // dispatch channel goes away. Online-ness is derived from `send`.
    if (state !== undefined) state.send = undefined
  }

  touch(deviceId: DeviceId, digest: HostStateDigest): void {
    const state = this.#hosts.get(deviceId)
    if (state !== undefined) {
      state.lastSeenMs = Date.now()
      state.digest = digest
    }
  }

  /** Rows for peers we have heard from; offline rows included, marked by `online`. */
  list(): readonly (HostStateDigest & { online: boolean })[] {
    const rows: (HostStateDigest & { online: boolean })[] = []
    for (const [deviceId, state] of this.#hosts) {
      rows.push({
        ...(state.digest ?? {
          deviceId,
          nickname: state.identity.displayName,
          os: 'unknown',
          lanAddress: 'unknown',
          reportedAtMs: state.lastSeenMs,
        }),
        online: state.send !== undefined,
      })
    }
    return rows
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
  findForDispatch(nameOrId: string): HostConnectionState | undefined {
    if (nameOrId.length === 0) return undefined
    const direct = this.#hosts.get(nameOrId as DeviceId)
    if (direct !== undefined && direct.send !== undefined) return direct
    for (const state of this.#hosts.values()) {
      if (state.send === undefined) continue
      if (state.identity.displayName === nameOrId) return state
      if (state.digest?.nickname === nameOrId) return state
    }
    return undefined
  }

  /** Capabilities come from the authorized identity, never from the wire. */
  hasCap(deviceId: DeviceId, cap: FedCapability): boolean {
    return this.#hosts.get(deviceId)?.identity.caps.includes(cap) ?? false
  }

  isOnline(deviceId: DeviceId): boolean {
    return this.#hosts.get(deviceId)?.send !== undefined
  }
}
