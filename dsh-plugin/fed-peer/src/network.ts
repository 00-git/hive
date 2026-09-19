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
import { networkInterfaces } from 'node:os'

/**
 * Interface names that identify a tunnel adapter. Deliberately broad: a missed
 * match means listening on nothing (loud, safe), while a false positive could
 * mean listening on a public NIC — so this errs toward specificity on names
 * that cannot plausibly be physical adapters.
 */
const VPN_NAME_PATTERN = /(openp2p|wintun|wireguard|tailscale|zerotier|vpn|tun\d|tap\d|utun)/i

export interface DetectedAddress {
  address: string
  iface: string
}

/** First non-internal IPv4 on an interface that looks like a tunnel, if any. */
export function detectVpnAddress(): DetectedAddress | undefined {
  for (const [name, entries] of Object.entries(networkInterfaces())) {
    if (!VPN_NAME_PATTERN.test(name)) continue
    for (const entry of entries ?? []) {
      if (entry.family !== 'IPv4' || entry.internal) continue
      return { address: entry.address, iface: name }
    }
  }
  return undefined
}

export type ListenTarget =
  /** Bound to a discovered tunnel address. */
  | { mode: 'vpn'; address: string; iface: string }
  /** An explicit operator setting; taken as-is, including 0.0.0.0. */
  | { mode: 'explicit'; address: string }
  /** Nothing to bind — stay closed. */
  | { mode: 'refused'; reason: string }

/**
 * Resolve the bind address. An explicit setting always wins, because the
 * operator may be deliberately exposing a different interface; absence of a
 * setting is what triggers detection, and a failed detection is what refuses.
 */
export function resolveListenTarget(configured: string | undefined): ListenTarget {
  const value = typeof configured === 'string' ? configured.trim() : ''
  if (value.length > 0) return { mode: 'explicit', address: value }
  const detected = detectVpnAddress()
  if (detected === undefined) {
    return {
      mode: 'refused',
      reason: 'no VPN interface found — listener stays closed (start OpenP2P, or set 监听地址 explicitly to override)',
    }
  }
  return { mode: 'vpn', address: detected.address, iface: detected.iface }
}
