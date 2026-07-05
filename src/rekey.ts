/**
 * CORD-06 — Rekeys and Refoundings: kind 3303 blobs, locators, continuity,
 * removal detection, and race convergence.
 */
import { v2 as nip44 } from 'nostr-tools/nip44'
import {
  bytesEqual,
  bytesToHex,
  compareBytes,
  concat,
  hexToBytes,
  u64be,
  ZERO32,
} from './bytes.js'
import { epochKeyCommitment, recipientLocator } from './derive.js'
import { pubkeyOf, tag, tagValue, type Rumor } from './events.js'
import { makeRumor } from './events.js'

export const KIND_REKEY = 3303
export const RECIPIENTS_PER_EVENT = 120
export const WRAPPED_PLAINTEXT_LEN = 72 // scope_id[32] ‖ epoch_be[8] ‖ new_key[32]

/** id32(Scope): a channel_id, or all-zeroes for the community_root (never collides). */
export const SCOPE_ROOT = ZERO32

export interface RekeyBlob {
  locator: string // hex
  wrapped: string // base64 NIP-44 ciphertext under the Rotator↔recipient pairwise key
}

/** The fixed-width 72-byte wrapped plaintext: scope and epoch live INSIDE the ciphertext. */
export function packWrapped(scopeId: Uint8Array, epoch: number | bigint, newKey: Uint8Array): Uint8Array {
  if (scopeId.length !== 32 || newKey.length !== 32) throw new Error('bad lengths')
  return concat(scopeId, u64be(epoch), newKey)
}
export function unpackWrapped(b: Uint8Array): { scopeId: Uint8Array; epoch: bigint; newKey: Uint8Array } {
  if (b.length !== WRAPPED_PLAINTEXT_LEN) throw new Error('wrapped plaintext must be 72 bytes')
  return {
    scopeId: b.slice(0, 32),
    epoch: new DataView(b.buffer, b.byteOffset + 32, 8).getBigUint64(0, false),
    newKey: b.slice(40, 72),
  }
}

export interface RotationParams {
  rotatorSk: Uint8Array // the Rotator's REAL key (the seal's npub)
  recipients: string[] // xonly hex — the surviving members
  scopeId: Uint8Array // channel_id or SCOPE_ROOT
  newEpoch: number
  prevEpoch: number
  prevKey: Uint8Array // the key being rotated away from
  newKey: Uint8Array
  created_at?: number
}

/** Build the kind 3303 rumors for one rotation, chunked at 120 recipients per event. */
export function buildRotation(p: RotationParams): Rumor[] {
  const rotatorPk = pubkeyOf(p.rotatorSk)
  const prevcommit = bytesToHex(epochKeyCommitment(p.prevEpoch, p.prevKey))
  const plaintext = packWrapped(p.scopeId, p.newEpoch, p.newKey)

  const blobs: RekeyBlob[] = p.recipients.map(rcpt => ({
    locator: bytesToHex(
      recipientLocator(hexToBytes(rotatorPk), hexToBytes(rcpt), p.scopeId, p.newEpoch),
    ),
    // NIP-44 ciphertext under the Rotator↔recipient pairwise key. NIP-44 v2
    // plaintext is a string, so the 72 raw bytes ride base64-encoded inside.
    wrapped: nip44.encrypt(
      Buffer.from(plaintext).toString('base64'),
      nip44.utils.getConversationKey(p.rotatorSk, rcpt),
    ),
  }))

  const n = Math.max(1, Math.ceil(blobs.length / RECIPIENTS_PER_EVENT))
  const rumors: Rumor[] = []
  for (let i = 0; i < n; i++) {
    const chunk = blobs.slice(i * RECIPIENTS_PER_EVENT, (i + 1) * RECIPIENTS_PER_EVENT)
    rumors.push(
      makeRumor({
        kind: KIND_REKEY,
        pubkey: rotatorPk,
        content: JSON.stringify(chunk),
        tags: [
          ['scope', bytesToHex(p.scopeId)],
          ['newepoch', String(p.newEpoch)],
          ['prevepoch', String(p.prevEpoch)],
          ['prevcommit', prevcommit],
          ['chunk', String(i + 1), String(n)],
        ],
        created_at: p.created_at ?? 1722500000,
      }),
    )
  }
  return rumors
}

export type RekeyOutcome =
  | { status: 'rekeyed'; newKey: Uint8Array; newEpoch: number }
  | { status: 'removed' }
  | { status: 'incomplete' } // a missing chunk is never a removal — keep recovering
  | { status: 'gap' } // prevcommit mismatch with a higher prevepoch: fetch the gap first
  | { status: 'reject'; reason: string }

export interface ReceiveParams {
  mySk: Uint8Array
  currentKey: Uint8Array // the key I currently hold for this scope
  currentEpoch: number
  expectedScope: Uint8Array
  /** verified via the seal + folded Roster before anything is honored */
  rotatorAuthorized: boolean
}

/** Process the chunks of ONE rotation (already correlated by rotator + newepoch + prevcommit). */
export function receiveRotation(chunks: Rumor[], p: ReceiveParams): RekeyOutcome {
  if (chunks.length === 0) return { status: 'incomplete' }

  // holding a key is never authority
  if (!p.rotatorAuthorized) return { status: 'reject', reason: 'rotator not authorized' }

  const first = chunks[0]!
  const scope = tagValue(first, 'scope')!
  const newEpoch = Number(tagValue(first, 'newepoch'))
  const prevEpoch = Number(tagValue(first, 'prevepoch'))
  const prevcommit = tagValue(first, 'prevcommit')!
  const rotator = first.pubkey

  // all chunks of one rotation carry identical continuity fields + one rotator
  for (const c of chunks) {
    if (
      c.pubkey !== rotator ||
      tagValue(c, 'scope') !== scope ||
      tagValue(c, 'newepoch') !== String(newEpoch) ||
      tagValue(c, 'prevcommit') !== prevcommit
    )
      return { status: 'reject', reason: 'chunks are not one rotation' }
  }

  if (!bytesEqual(hexToBytes(scope), p.expectedScope))
    return { status: 'reject', reason: 'scope mismatch' }

  // continuity: the commitment over the key I hold must equal prevcommit
  const myCommit = bytesToHex(epochKeyCommitment(prevEpoch, p.currentKey))
  if (myCommit !== prevcommit) {
    if (prevEpoch > p.currentEpoch) return { status: 'gap' } // missed a rotation
    return { status: 'reject', reason: 'fork or garbage' }
  }

  // find my locator across all held chunks
  const myPk = pubkeyOf(p.mySk)
  const myLocator = bytesToHex(
    recipientLocator(hexToBytes(rotator), hexToBytes(myPk), p.expectedScope, newEpoch),
  )
  for (const c of chunks) {
    const blobs = JSON.parse(c.content) as RekeyBlob[]
    const mine = blobs.find(b => b.locator === myLocator)
    if (mine) {
      // one ECDH either side can compute — a NIP-46 bunker account opens its
      // blob with a single nip44_decrypt, no raw-key access needed
      const convKey = nip44.utils.getConversationKey(p.mySk, rotator)
      const plaintext = new Uint8Array(Buffer.from(nip44.decrypt(mine.wrapped, convKey), 'base64'))
      const { scopeId, epoch, newKey } = unpackWrapped(plaintext)
      // verify the INNER scope and epoch against the event's tags before accepting
      if (!bytesEqual(scopeId, p.expectedScope) || epoch !== BigInt(newEpoch))
        return { status: 'reject', reason: 'inner scope/epoch does not match tags' }
      return { status: 'rekeyed', newKey, newEpoch }
    }
  }

  // removed ONLY once all n chunks are held and none contains my locator
  const n = Number(tag(first, 'chunk')?.[2])
  const seen = new Set(chunks.map(c => tag(c, 'chunk')?.[1]))
  if (seen.size < n) return { status: 'incomplete' }
  return { status: 'removed' }
}

// ---- §3 races ----------------------------------------------------------------

/** Among authorized candidates at the same continuity point, the
 * lexicographically lowest new key wins — every client computes the same winner. */
export function resolveRace(candidateNewKeys: Uint8Array[]): Uint8Array {
  if (candidateNewKeys.length === 0) throw new Error('no candidates')
  return candidateNewKeys.reduce((a, b) => (compareBytes(a, b) <= 0 ? a : b))
}

/** The same-epoch heal is DOWN-only: a settled epoch re-converges solely to a
 * strictly lower sibling; a higher sibling can never re-fork it. */
export function healSettledEpoch(settled: Uint8Array, sibling: Uint8Array): Uint8Array {
  return compareBytes(sibling, settled) < 0 ? sibling : settled
}
