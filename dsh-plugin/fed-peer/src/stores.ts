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
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  generateIdentity,
  restoreIdentity,
  type PendingTrust,
  type PeerIdentityMaterial,
  type TrustedPeerRow,
  type TrustPersistence,
} from '../../fed-protocol/lib/host/index.js'
import type { DeviceId, PublicKeyB64 } from '../../fed-protocol/lib/host/index.js'

/** Write-then-rename: a crash mid-write must not leave a truncated key file. */
function writeJsonAtomic(file: string, value: unknown): void {
  const temp = `${file}.tmp`
  writeFileSync(temp, JSON.stringify(value, null, 2), 'utf8')
  renameSync(temp, file)
}

function readJson(file: string): unknown {
  if (!existsSync(file)) return undefined
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    // A corrupt file is treated as absent rather than fatal: refusing to start
    // would strand the machine, and every caller has a sane empty fallback.
    return undefined
  }
}

export interface LoadedIdentity {
  identity: PeerIdentityMaterial
  /** True the first time this machine ever ran — worth telling the operator once. */
  created: boolean
}

/**
 * Load this machine's identity, minting one on first run.
 *
 * The private key never leaves this file, so identity is not something another
 * peer can grant, revoke, or transfer — the whole point of dropping tokens.
 */
export function loadOrCreateIdentity(stateDir: string): LoadedIdentity {
  const file = join(stateDir, 'identity.json')
  const parsed = readJson(file) as { publicKey?: unknown; privateKeyPem?: unknown; createdAtMs?: unknown } | undefined
  if (parsed !== undefined && typeof parsed.publicKey === 'string' && typeof parsed.privateKeyPem === 'string') {
    try {
      const identity = restoreIdentity(
        parsed.publicKey as PublicKeyB64,
        parsed.privateKeyPem,
        typeof parsed.createdAtMs === 'number' ? parsed.createdAtMs : Date.now(),
      )
      return { identity, created: false }
    } catch {
      // The stored key does not match its own id (hand-edited or truncated).
      // Falling through mints a new identity, which is the safe direction: the
      // alternative is running with an identity nobody can verify.
    }
  }
  const identity = generateIdentity()
  mkdirSync(stateDir, { recursive: true })
  writeJsonAtomic(file, identity)
  return { identity, created: true }
}

/**
 * Trust-table persistence. Callers pass the same dir as the identity.
 *
 * One document holds both the trusted rows and the pending requests, which is
 * what lets the operator CLI be a pure file editor (no listener to connect to)
 * and lets the two processes on a machine see each other's decisions.
 */
export function trustPersistenceFor(stateDir: string): TrustPersistence {
  const file = join(stateDir, 'trusted-peers.json')
  return {
    load: () => {
      const parsed = readJson(file)
      // A bare array is the pre-D-020 layout; reading it keeps an upgrade from
      // silently dropping the peers an operator already vouched for.
      if (Array.isArray(parsed)) return { trusted: parsed as readonly TrustedPeerRow[], pending: [] }
      if (typeof parsed !== 'object' || parsed === null) return undefined
      const snapshot = parsed as { trusted?: unknown; pending?: unknown }
      return {
        trusted: Array.isArray(snapshot.trusted) ? (snapshot.trusted as readonly TrustedPeerRow[]) : [],
        pending: Array.isArray(snapshot.pending) ? (snapshot.pending as readonly PendingTrust[]) : [],
      }
    },
    save: (snapshot) => {
      try {
        mkdirSync(stateDir, { recursive: true })
        writeJsonAtomic(file, snapshot)
      } catch {
        // A failed persist must not break a live connection; the operator will
        // simply be asked to confirm again after a restart.
      }
    },
  }
}

/**
 * One remembered address for a peer.
 *
 * Addresses are hints, never identity: the same peer may be reachable at
 * several (LAN address, OpenP2P local forward port), and a stale entry costs
 * one failed dial, not a security decision.
 */
export interface KnownPeer {
  deviceId: DeviceId
  publicKey: PublicKeyB64
  nickname: string
  /** Where WE reach it. Already a local forward address when tunneled. */
  address: string
  /** Whether the local operator has confirmed it. Untrusted rows are dial candidates only. */
  trusted: boolean
  lastSeenMs: number
}

/**
 * Address book for the mesh. Deliberately separate from the trust table: this
 * one is a cache that gossip may append to freely, while trust is only ever
 * written by an operator.
 */
export class PeerTable {
  readonly #rows = new Map<DeviceId, KnownPeer>()
  readonly #file: string | undefined

  constructor(stateDir?: string) {
    this.#file = stateDir === undefined ? undefined : join(stateDir, 'peers.json')
    const parsed = this.#file === undefined ? undefined : readJson(this.#file)
    for (const row of Array.isArray(parsed) ? (parsed as readonly KnownPeer[]) : []) {
      if (typeof row?.deviceId === 'string' && typeof row?.address === 'string') this.#rows.set(row.deviceId, row)
    }
  }

  #persist(): void {
    if (this.#file === undefined) return
    try {
      writeJsonAtomic(this.#file, [...this.#rows.values()])
    } catch {
      // Cache only — never worth failing a connection over.
    }
  }

  upsert(peer: Omit<KnownPeer, 'lastSeenMs'> & { lastSeenMs?: number }): KnownPeer {
    const row: KnownPeer = { ...peer, lastSeenMs: peer.lastSeenMs ?? Date.now() }
    this.#rows.set(row.deviceId, row)
    this.#persist()
    return row
  }

  get(deviceId: DeviceId): KnownPeer | undefined {
    return this.#rows.get(deviceId)
  }

  remove(deviceId: DeviceId): boolean {
    const removed = this.#rows.delete(deviceId)
    if (removed) this.#persist()
    return removed
  }

  list(): readonly KnownPeer[] {
    return [...this.#rows.values()]
  }

  /** Dial candidates: everyone we know an address for, except ourselves. */
  dialCandidates(selfId: DeviceId): readonly KnownPeer[] {
    return this.list().filter((peer) => peer.deviceId !== selfId && peer.address.length > 0)
  }
}

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
export function keepConnection(localId: DeviceId, remoteId: DeviceId, remoteInitiated: boolean): boolean {
  const localIsSmaller = String(localId) < String(remoteId)
  return remoteInitiated ? !localIsSmaller : localIsSmaller
}
