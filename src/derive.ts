/**
 * CORD-02 Appendix A — frozen derivations.
 *
 * A.1 hkdf(secret, label, id, epoch)
 * A.2 group_key(label, secret, id, epoch)
 * A.3 scalar_normalize
 * A.4 community_id
 * A.5 epoch-key commitment
 * A.6 label table (locator helpers below)
 */
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { schnorr, secp256k1 } from '@noble/curves/secp256k1'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { bytesToHex, concat, u64be, utf8, ZERO32 } from './bytes.js'

/**
 * A.1 — HKDF-SHA256 with zero-length salt.
 * info = utf8(label) || 0x00 || id[32] || epoch_be[8]
 * The id is always present (all-zeroes where a label has no meaningful id);
 * the epoch is the only omittable field. The scalar_normalize retry counter
 * appends after whatever fields are present.
 */
export function hkdfConcord(
  secret: Uint8Array,
  label: string,
  id: Uint8Array = ZERO32,
  epoch?: number | bigint,
  retryCounter?: number,
): Uint8Array {
  if (id.length !== 32) throw new Error('id must be a raw 32-byte value')
  let info = concat(utf8(label), new Uint8Array([0x00]), id)
  if (epoch !== undefined) info = concat(info, u64be(epoch))
  if (retryCounter !== undefined) info = concat(info, new Uint8Array([retryCounter]))
  return hkdf(sha256, secret, undefined, info, 32)
}

function isValidScalar(seed: Uint8Array): boolean {
  const x = BigInt('0x' + bytesToHex(seed))
  return x > 0n && x < secp256k1.CURVE.n
}

/**
 * A.3 — scalar_normalize. If the seed is not a valid secp256k1 scalar,
 * append one incrementing counter byte to the hkdf info and retry.
 * Deterministic across implementations; the reject branch is ~2^-128 rare.
 */
export function scalarNormalize(
  secret: Uint8Array,
  label: string,
  id: Uint8Array,
  epoch?: number | bigint,
): Uint8Array {
  let seed = hkdfConcord(secret, label, id, epoch)
  let counter = 0
  while (!isValidScalar(seed)) {
    if (counter > 255) throw new Error('scalar_normalize exhausted counter space')
    seed = hkdfConcord(secret, label, id, epoch, counter)
    counter++
  }
  return seed
}

export interface GroupKey {
  sk: Uint8Array // signs the plane's giftwraps
  pk: string // x-only pubkey hex — the Stream address (authors filter)
  convKey: Uint8Array // NIP-44 self-ECDH; encrypts the wrap
}

/** A.2 — group_key: seed → valid secret key → x-only address + conversation key. */
export function groupKey(
  label: string,
  secret: Uint8Array,
  id: Uint8Array = ZERO32,
  epoch?: number | bigint,
): GroupKey {
  const sk = scalarNormalize(secret, label, id, epoch)
  const pk = bytesToHex(schnorr.getPublicKey(sk))
  const convKey = nip44.utils.getConversationKey(sk, pk) // self-ECDH
  return { sk, pk, convKey }
}

/** A.4 — community_id: a plain SHA-256 commitment, NOT the hkdf construction. */
export function communityId(ownerXonly: Uint8Array, ownerSalt: Uint8Array): Uint8Array {
  if (ownerXonly.length !== 32 || ownerSalt.length !== 32)
    throw new Error('owner_xonly and owner_salt must be 32 bytes')
  return sha256(concat(utf8('concord/community'), ownerXonly, ownerSalt))
}

/** A.5 — epoch-key commitment (CORD-06 prevcommit). */
export function epochKeyCommitment(prevEpoch: number | bigint, prevKey: Uint8Array): Uint8Array {
  return sha256(concat(utf8('concord/epoch-key-commitment'), u64be(prevEpoch), prevKey))
}

// ---- A.6 label table -------------------------------------------------------

/** Control Plane group key: community_root-keyed, id = community_id, epoch. */
export const controlKey = (root: Uint8Array, cid: Uint8Array, epoch: number | bigint) =>
  groupKey('concord/control', root, cid, epoch)

/** A Channel's group key (public: secret = community_root; private: channel key). */
export const channelKey = (secret: Uint8Array, channelId: Uint8Array, epoch: number | bigint) =>
  groupKey('concord/channel', secret, channelId, epoch)

/** Guestbook Plane group key. */
export const guestbookKey = (root: Uint8Array, cid: Uint8Array, epoch: number | bigint) =>
  groupKey('concord/guestbook', root, cid, epoch)

/** Dissolution tombstone address — community_id alone, id all-zeroes, NO epoch. */
export const dissolvedKey = (cid: Uint8Array) => groupKey('concord/dissolved', cid, ZERO32)

/** A member's Grant coordinate (an edition eid) — bound to community_id, keyless/epochless. */
export const grantLocator = (cid: Uint8Array, memberXonly: Uint8Array) =>
  hkdfConcord(cid, 'concord/grant', memberXonly)

/** The Banlist coordinate. */
export const banlistLocator = (cid: Uint8Array) => hkdfConcord(cid, 'concord/banlist', ZERO32)

/** A creator's invite Registry coordinate. */
export const inviteLinksLocator = (cid: Uint8Array, creatorXonly: Uint8Array) =>
  hkdfConcord(cid, 'concord/invite-links', creatorXonly)

/** Channel rekey address, derived from the PRIOR secret (CORD-06). */
export const rekeyPseudonym = (
  priorRoot: Uint8Array,
  channelId: Uint8Array,
  newEpoch: number | bigint,
) => groupKey('concord/rekey-pseudonym', priorRoot, channelId, newEpoch)

/** Base rekey address, derived from the PRIOR root (CORD-06). */
export const baseRekeyPseudonym = (
  priorRoot: Uint8Array,
  cid: Uint8Array,
  newEpoch: number | bigint,
) => groupKey('concord/base-rekey-pseudonym', priorRoot, cid, newEpoch)

/**
 * Rekey blob locator (CORD-06 §2) — derived from PUBLIC inputs:
 * hkdf(rotator_xonly || recipient_xonly, "concord/recipient-pseudonym", scope_id, epoch)
 */
export const recipientLocator = (
  rotatorXonly: Uint8Array,
  recipientXonly: Uint8Array,
  scopeId: Uint8Array,
  epoch: number | bigint,
) => hkdfConcord(concat(rotatorXonly, recipientXonly), 'concord/recipient-pseudonym', scopeId, epoch)

// ---- CORD-05 token derivations ---------------------------------------------

/** Decrypts the bundle. */
export const inviteBundleKey = (token: Uint8Array) => hkdfConcord(token, 'concord/invite-key')
/** The addressable coordinate. */
export const inviteBundleId = (token: Uint8Array) => hkdfConcord(token, 'concord/invite-locator')
/** Signs the bundle event — normalizes to a valid key exactly as any derived scalar (A.3). */
export function inviteBundleSigner(token: Uint8Array): { sk: Uint8Array; pk: string } {
  const sk = scalarNormalize(token, 'concord/invite-signer', ZERO32)
  return { sk, pk: bytesToHex(schnorr.getPublicKey(sk)) }
}
