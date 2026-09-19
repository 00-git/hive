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
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto'

/**
 * Stable peer identity, self-derived from a public key. Branded so a bare
 * string can never be passed where an identity is required (dsh 跨边界 id
 * 品牌化约定). Defined here rather than in auth.ts because auth.ts consumes
 * identities and this module must stay import-free at runtime.
 */
declare const deviceIdBrand: unique symbol
export type DeviceId = string & { readonly [deviceIdBrand]: true }

/** Raw Ed25519 public key, base64url of the 32-byte JWK `x` coordinate. */
export type PublicKeyB64 = string

/** PKCS8 PEM. Never crosses the wire; never leaves the machine. */
export type PrivateKeyPem = string

/** The on-disk identity material one peer owns. */
export interface PeerIdentityMaterial {
  readonly deviceId: DeviceId
  readonly publicKey: PublicKeyB64
  readonly privateKeyPem: PrivateKeyPem
  /** Creation time, audit only — never used for any decision. */
  readonly createdAtMs: number
}

/** Length of the human-facing device id. 16 symbols × 5 bits = 80 bits. */
const DEVICE_ID_LENGTH = 16

/** Magic + version so a future scheme can coexist during migration. */
const HANDSHAKE_DOMAIN = 'hive-handshake-v1'
const SAS_DOMAIN = 'hive-sas-v1'

/** Lowercase RFC4648 alphabet (no padding): safe in CLI output and on the wire. */
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

/**
 * Deterministic base32 (no padding) so an id is reproducible from the key on
 * any peer without a shared table.
 */
function base32Lower(bytes: Uint8Array): string {
  let out = ''
  let buffer = 0
  let bits = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31]
  return out
}

/** Rebuild a KeyObject from the compact wire form (raw 32-byte JWK `x`). */
function publicKeyFromWire(publicKey: PublicKeyB64): ReturnType<typeof createPublicKey> {
  if (typeof publicKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(publicKey)) {
    throw new Error('publicKey must be a base64url Ed25519 coordinate (43 chars)')
  }
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' })
}

function privateKeyFromPem(privateKeyPem: PrivateKeyPem): ReturnType<typeof createPrivateKey> {
  return createPrivateKey(privateKeyPem)
}

/**
 * Derive the self-certifying id from a public key. Pure and local: any peer can
 * recompute it, so no peer needs to be told who anyone is.
 */
export function deriveDeviceId(publicKey: PublicKeyB64): DeviceId {
  const key = publicKeyFromWire(publicKey)
  const raw = key.export({ format: 'jwk' }) as { x?: string }
  if (typeof raw.x !== 'string') throw new Error('ed25519 key has no x coordinate')
  const digest = createHash('sha256').update(raw.x, 'utf8').digest()
  return base32Lower(digest).slice(0, DEVICE_ID_LENGTH) as DeviceId
}

/** Mint a fresh peer identity. Called once per machine, then persisted. */
export function generateIdentity(): PeerIdentityMaterial {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string }
  const publicKeyB64 = jwk.x
  return {
    deviceId: deriveDeviceId(publicKeyB64),
    publicKey: publicKeyB64,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    createdAtMs: Date.now(),
  }
}

/**
 * Rebuild the identity material from persisted parts, verifying that the stored
 * deviceId still derives from the stored key. A mismatch means the file was
 * edited (or is corrupt) — refuse rather than silently adopt a new identity.
 */
export function restoreIdentity(publicKey: PublicKeyB64, privateKeyPem: PrivateKeyPem, createdAtMs = 0): PeerIdentityMaterial {
  return { deviceId: deriveDeviceId(publicKey), publicKey, privateKeyPem, createdAtMs }
}

/** Fresh 32-byte nonce, base64url. Per-connection: never reused. */
export function createNonce(): string {
  return randomBytes(32).toString('base64url')
}

/**
 * Canonical handshake message. Both ids are always present in fixed DIALER,
 * ACCEPTOR order — callers pass them in that order no matter which side is
 * signing, so the two proofs below cannot drift apart.
 */
function handshakeMessage(nonce: string, dialerId: DeviceId, acceptorId: DeviceId): Buffer {
  return Buffer.from(`${HANDSHAKE_DOMAIN}\n${nonce}\n${dialerId}\n${acceptorId}`, 'utf8')
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
export function signHandshake(privateKeyPem: PrivateKeyPem, nonce: string, dialerId: DeviceId, acceptorId: DeviceId): string {
  const key = privateKeyFromPem(privateKeyPem)
  // Ed25519 takes a null digest — the algorithm is implied by the key type.
  return sign(null, handshakeMessage(nonce, dialerId, acceptorId), key).toString('base64url')
}

/**
 * Verify a peer's proof. `dialerId`/`acceptorId` must be passed in the same
 * fixed roles the signer used, so a proof made for one direction cannot be
 * reflected back at its maker.
 */
export function verifyHandshake(
  publicKey: PublicKeyB64,
  nonce: string,
  dialerId: DeviceId,
  acceptorId: DeviceId,
  signature: string,
): boolean {
  try {
    const key = publicKeyFromWire(publicKey)
    return verify(null, handshakeMessage(nonce, dialerId, acceptorId), key, Buffer.from(signature, 'base64url'))
  } catch {
    // Malformed key/signature is a failed verification, never a thrown error:
    // this runs inside the message loop where a throw would kill the process.
    return false
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
export function computeSas(publicKeyA: PublicKeyB64, publicKeyB: PublicKeyB64): string {
  const [first, second] = [publicKeyA, publicKeyB].sort()
  const digest = createHash('sha256').update(`${SAS_DOMAIN}\n${first}\n${second}`, 'utf8').digest()
  const numeric = digest.readUInt32BE(0) % 1_000_000
  return String(numeric).padStart(6, '0')
}

/**
 * Human-facing grouping of a device id (4-4-4-4). Display only — always compare
 * the SAS for trust; never compare ids by eye.
 */
export function formatDeviceId(deviceId: DeviceId): string {
  const raw = String(deviceId)
  return raw.replace(/(.{4})(?=.)/g, '$1-')
}
