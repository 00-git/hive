/**
 * Host registry + device token store (gateway side).
 * Tokens are stored hashed only; identity resolution is the auth choke point.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import {
  FedCapability,
  hashToken,
  type DeviceId,
  type DeviceIdentity,
  type DeviceToken,
  type DeviceTokenStore,
  type HostStateDigest,
} from '../../fed-protocol/lib/host/index.js'

function isKnownCapValue(value: string): value is FedCapability {
  return (Object.values(FedCapability) as string[]).includes(value)
}

export interface HostConnectionState {
  identity: DeviceIdentity
  /** Live dispatch channel; undefined while the host is mid-reconnect. */
  send: ((frame: unknown) => void) | undefined
  lastSeenMs: number
  digest: HostStateDigest | undefined
}

export class HostRegistry implements DeviceTokenStore {
  readonly #tokens = new Map<string, { deviceId: DeviceId; identity: DeviceIdentity; revoked: boolean }>()
  readonly #hosts = new Map<DeviceId, HostConnectionState>()
  #nextDeviceId = 1
  #file: string | undefined

  /**
   * Persist the registry (token HASHES + identities — never raw tokens) so a
   * gateway restart does not force re-pairing (D-013).
   */
  setPersistence(file: string | undefined): void {
    this.#file = file
    if (file !== undefined && existsSync(file)) {
      try {
        const parsed = JSON.parse(readFileSync(file, 'utf8')) as {
          nextDeviceId?: number
          devices?: readonly { tokenHash: string; deviceId: string; displayName: string; caps: readonly string[]; pairedAt: number; revoked?: boolean }[]
        }
        for (const device of parsed.devices ?? []) {
          if (typeof device.tokenHash !== 'string' || typeof device.deviceId !== 'string') continue
          const identity: DeviceIdentity = {
            deviceId: device.deviceId as DeviceId,
            displayName: device.displayName,
            caps: device.caps.filter(isKnownCapValue),
            pairedAt: device.pairedAt,
          }
          this.#tokens.set(device.tokenHash, { deviceId: identity.deviceId, identity, revoked: device.revoked === true })
        }
        if (typeof parsed.nextDeviceId === 'number' && parsed.nextDeviceId > this.#nextDeviceId) {
          this.#nextDeviceId = parsed.nextDeviceId
        }
      } catch {
        // Corrupt registry file: start empty (hosts self-heal via re-pairing).
      }
    }
  }

  #persist(): void {
    if (this.#file === undefined) return
    try {
      const devices = [...this.#tokens.entries()].map(([tokenHash, entry]) => ({
        tokenHash,
        deviceId: entry.deviceId,
        displayName: entry.identity.displayName,
        caps: entry.identity.caps,
        pairedAt: entry.identity.pairedAt,
        revoked: entry.revoked,
      }))
      mkdirSync(dirname(this.#file), { recursive: true })
      writeFileSync(this.#file, JSON.stringify({ nextDeviceId: this.#nextDeviceId, devices }, null, 2), 'utf8')
    } catch {
      // Persist failures must not break the pairing pipeline.
    }
  }

  mintDeviceId(): DeviceId {
    return `host-${String(this.#nextDeviceId++).padStart(3, '0')}` as DeviceId
  }

  /** Register a freshly approved device: hash-only token storage (D-004). */
  registerToken(deviceId: DeviceId, rawToken: string, identity: DeviceIdentity): void {
    this.#tokens.set(hashToken(rawToken as DeviceToken), { deviceId, identity, revoked: false })
    this.#persist()
  }

  /** Revoke: token stops resolving immediately; the host must re-pair. */
  revoke(deviceId: DeviceId): boolean {
    let revoked = false
    for (const entry of this.#tokens.values()) {
      if (entry.deviceId === deviceId && !entry.revoked) {
        entry.revoked = true
        revoked = true
      }
    }
    if (revoked) this.#persist()
    return revoked
  }

  /** DeviceTokenStore.resolve ??the ONLY identity source (?????? choke point). */
  resolve(token: DeviceToken): DeviceIdentity | undefined {
    const hash = hashToken(token)
    const entry = this.#tokens.get(hash)
    if (entry === undefined || entry.revoked) return undefined
    return entry.identity
  }

  /** Attach or re-attach a live connection for an authenticated host. */
  bind(identity: DeviceIdentity, send: (frame: unknown) => void): void {
    this.#hosts.set(identity.deviceId, {
      identity,
      send,
      lastSeenMs: Date.now(),
      digest: this.#hosts.get(identity.deviceId)?.digest,
    })
  }

  unbind(deviceId: DeviceId): void {
    const state = this.#hosts.get(deviceId)
    if (state !== undefined) state.send = undefined
  }

  touch(deviceId: DeviceId, digest: HostStateDigest): void {
    const state = this.#hosts.get(deviceId)
    if (state !== undefined) {
      state.lastSeenMs = Date.now()
      state.digest = digest
    }
  }

  list(): readonly HostStateDigest[] {
    const digests: HostStateDigest[] = []
    for (const [deviceId, state] of this.#hosts) {
      digests.push(state.digest ?? {
        deviceId,
        displayName: state.identity.displayName,
        os: 'unknown',
        lanAddress: 'unknown',
        reportedAtMs: state.lastSeenMs,
      })
    }
    return digests
  }

  /** Resolve a host by deviceId or displayName for dispatch. */
  findForDispatch(nameOrId: string): HostConnectionState | undefined {
    const direct = this.#hosts.get(nameOrId as DeviceId)
    if (direct !== undefined && direct.send !== undefined) return direct
    for (const state of this.#hosts.values()) {
      if (state.identity.displayName === nameOrId && state.send !== undefined) return state
    }
    return undefined
  }

  hasCap(deviceId: DeviceId, cap: FedCapability): boolean {
    return this.#hosts.get(deviceId)?.identity.caps.includes(cap) ?? false
  }
}
