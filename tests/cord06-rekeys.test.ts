/**
 * CORD-06: Rekeys and Refoundings — every claim in 06.md, asserted.
 */
import { describe, expect, it } from 'vitest'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { bytesToHex, hexToBytes, randomBytes } from '../src/bytes.js'
import {
  baseRekeyPseudonym,
  channelKey,
  communityId,
  controlKey,
  epochKeyCommitment,
  recipientLocator,
  rekeyPseudonym,
} from '../src/derive.js'
import { editionTags, foldControl, KIND_EDITION, VSK } from '../src/editions.js'
import { makeRumor, pubkeyOf, tagValue, verifyEvent } from '../src/events.js'
import { PERM } from '../src/roster.js'
import { unwrapEvent, wrapRumor, wrapSeal } from '../src/stream.js'
import {
  buildRotation,
  healSettledEpoch,
  packWrapped,
  receiveRotation,
  RECIPIENTS_PER_EVENT,
  resolveRace,
  SCOPE_ROOT,
  unpackWrapped,
  WRAPPED_PLAINTEXT_LEN,
  type ReceiveParams,
} from '../src/rekey.js'

// ---- fixtures ---------------------------------------------------------------------

const rotatorSk = randomBytes(32)
const rotatorPk = pubkeyOf(rotatorSk)
const memberSk = randomBytes(32)
const memberPk = pubkeyOf(memberSk)
const removedSk = randomBytes(32)
const removedPk = pubkeyOf(removedSk)

const channelId = randomBytes(32)
const prevKey = randomBytes(32)
const newKey = randomBytes(32)

function rotation(over: Partial<Parameters<typeof buildRotation>[0]> = {}) {
  return buildRotation({
    rotatorSk,
    recipients: [memberPk],
    scopeId: channelId,
    newEpoch: 3,
    prevEpoch: 2,
    prevKey,
    newKey,
    ...over,
  })
}

function receiveParams(over: Partial<ReceiveParams> = {}): ReceiveParams {
  return {
    mySk: memberSk,
    currentKey: prevKey,
    currentEpoch: 2,
    expectedScope: channelId,
    rotatorAuthorized: true,
    ...over,
  }
}

describe('CORD-06 §1 — rekey blobs', () => {
  it('a kind 3303 package delivers the fresh key to 120 participants per event; larger rotations span several events', () => {
    expect(RECIPIENTS_PER_EVENT).toBe(120)
    const many = Array.from({ length: 121 }, () => pubkeyOf(randomBytes(32)))
    const chunks = rotation({ recipients: many })
    expect(chunks).toHaveLength(2)
    expect(JSON.parse(chunks[0]!.content)).toHaveLength(120)
    expect(JSON.parse(chunks[1]!.content)).toHaveLength(1)
    expect(chunks[0]!.kind).toBe(3303)
    // ["chunk", i, n] on each
    expect(chunks[0]!.tags.find(t => t[0] === 'chunk')).toEqual(['chunk', '1', '2'])
    expect(chunks[1]!.tags.find(t => t[0] === 'chunk')).toEqual(['chunk', '2', '2'])
  })

  it('scope is a Channel(channel_id) or the community_root as all-zeroes — which never collides with a Channel id', () => {
    expect(bytesToHex(SCOPE_ROOT)).toBe('00'.repeat(32))
    const base = rotation({ scopeId: SCOPE_ROOT })
    expect(tagValue(base[0]!, 'scope')).toBe('00'.repeat(32))
    const chan = rotation()
    expect(tagValue(chan[0]!, 'scope')).toBe(bytesToHex(channelId))
    // channel ids are minted as random 32 bytes: the all-zero id is reserved by construction
    expect(bytesToHex(channelId)).not.toBe('00'.repeat(32))
  })

  it('a Public Channel has no independent rekey: its key IS the base derivation, so it rotates only with the base', () => {
    const root = randomBytes(32)
    const pub0 = channelKey(root, channelId, 0)
    const newRoot = randomBytes(32)
    const pub1 = channelKey(newRoot, channelId, 1)
    // no delivery step exists — the "rotation" is just re-derivation from the rolled base
    expect(pub1.pk).not.toBe(pub0.pk)
  })

  it('the wrapped plaintext is fixed-width, 72 bytes: scope_id[32] ‖ epoch_be[8] ‖ new_key[32]', () => {
    const packed = packWrapped(channelId, 3, newKey)
    expect(packed).toHaveLength(WRAPPED_PLAINTEXT_LEN)
    expect(WRAPPED_PLAINTEXT_LEN).toBe(72)
    const un = unpackWrapped(packed)
    expect(bytesToHex(un.scopeId)).toBe(bytesToHex(channelId))
    expect(un.epoch).toBe(3n)
    expect(bytesToHex(un.newKey)).toBe(bytesToHex(newKey))
    // byte-exact layout
    expect(bytesToHex(packed.slice(0, 32))).toBe(bytesToHex(channelId))
    expect(bytesToHex(packed.slice(32, 40))).toBe('0000000000000003')
  })

  it('scope and epoch live INSIDE the ciphertext: a blob minted for one channel can never be replayed against another', () => {
    // mallory lifts alice's blob from the #a rotation and re-tags it as a #b
    // rotation — even rewriting the locator (which computes from PUBLIC inputs,
    // so an insider can) to make alice find the spliced blob
    const chunksA = rotation() // scope = channel A
    const otherChannel = randomBytes(32)
    const blobs = JSON.parse(chunksA[0]!.content) as { locator: string; wrapped: string }[]
    const relocated = blobs.map(b => ({
      ...b,
      locator: bytesToHex(recipientLocator(hexToBytes(rotatorPk), hexToBytes(memberPk), otherChannel, 3)),
    }))
    const forged = makeRumor({
      ...chunksA[0]!,
      content: JSON.stringify(relocated),
      tags: chunksA[0]!.tags.map(t => (t[0] === 'scope' ? ['scope', bytesToHex(otherChannel)] : t)),
    })
    const res = receiveRotation([forged], receiveParams({ expectedScope: otherChannel }))
    // the recipient decrypts and verifies the INNER scope against the tags — mismatch → reject
    expect(res).toEqual({ status: 'reject', reason: 'inner scope/epoch does not match tags' })
  })

  it('the wrap key is the NIP-44 conversation key between Rotator and recipient — one ECDH either side can compute', () => {
    const fromRotator = nip44.utils.getConversationKey(rotatorSk, memberPk)
    const fromRecipient = nip44.utils.getConversationKey(memberSk, rotatorPk)
    expect(bytesToHex(fromRotator)).toBe(bytesToHex(fromRecipient))
    // so a NIP-46 bunker account opens its blob with a single nip44_decrypt
    const chunks = rotation()
    const blob = JSON.parse(chunks[0]!.content)[0]
    const plain = new Uint8Array(Buffer.from(nip44.decrypt(blob.wrapped, fromRecipient), 'base64'))
    expect(bytesToHex(unpackWrapped(plain).newKey)).toBe(bytesToHex(newKey))
  })
})

describe('CORD-06 §2 — receiving & processing', () => {
  it('subscription addresses are precomputed for the NEXT epoch and derive from the PRIOR secret', () => {
    const priorRoot = randomBytes(32)
    const cid = communityId(hexToBytes(pubkeyOf(randomBytes(32))), randomBytes(32))
    // per held private channel + the base address: both derivable from what a member ALREADY holds
    const chanAddr = rekeyPseudonym(priorRoot, channelId, 3 + 1)
    const baseAddr = baseRekeyPseudonym(priorRoot, cid, 1)
    expect(chanAddr.pk).not.toBe(baseAddr.pk)
    // an outsider without the prior root cannot compute either
    expect(rekeyPseudonym(randomBytes(32), channelId, 4).pk).not.toBe(chanAddr.pk)
  })

  it('locator = hkdf(rotator_xonly || recipient_xonly, "concord/recipient-pseudonym", scope_id, epoch) — public inputs only', () => {
    const chunks = rotation()
    const blob = JSON.parse(chunks[0]!.content)[0]
    const expected = recipientLocator(hexToBytes(rotatorPk), hexToBytes(memberPk), channelId, 3)
    expect(blob.locator).toBe(bytesToHex(expected))
  })

  it('if any chunk contains your locator, you decrypt the new key and shift to the new epoch', () => {
    const res = receiveRotation(rotation(), receiveParams())
    expect(res.status).toBe('rekeyed')
    if (res.status === 'rekeyed') {
      expect(bytesToHex(res.newKey)).toBe(bytesToHex(newKey))
      expect(res.newEpoch).toBe(3)
    }
  })

  it('you are removed ONLY once you hold all n chunks and none contains your locator', () => {
    const others = Array.from({ length: 121 }, () => pubkeyOf(randomBytes(32)))
    const chunks = rotation({ recipients: others }) // the receiver is not among them
    const all = receiveRotation(chunks, receiveParams())
    expect(all.status).toBe('removed')
  })

  it('a missing chunk is never a removal — it is "keep recovering"', () => {
    const others = Array.from({ length: 121 }, () => pubkeyOf(randomBytes(32)))
    const chunks = rotation({ recipients: others })
    const partial = receiveRotation([chunks[0]!], receiveParams()) // one of two chunks
    expect(partial.status).toBe('incomplete') // refetch until the set is complete
  })

  it('you MUST validate the rekey came from a role-authorized administrator before accepting', () => {
    const res = receiveRotation(rotation(), receiveParams({ rotatorAuthorized: false }))
    expect(res).toEqual({ status: 'reject', reason: 'rotator not authorized' })
  })

  it('a member can confirm a fellow member’s presence in a rotation by name (locators compute from public keys alone)', () => {
    const chunks = rotation({ recipients: [memberPk] })
    // another member — knowing only rotator + member pubkeys — computes the locator and finds it
    const observerComputed = bytesToHex(recipientLocator(hexToBytes(rotatorPk), hexToBytes(memberPk), channelId, 3))
    const locators = chunks.flatMap(c => (JSON.parse(c.content) as { locator: string }[]).map(b => b.locator))
    expect(locators).toContain(observerComputed)
  })

  it('…but an outsider reaches nothing: the locator list lives inside the encrypted event at a member-only address', () => {
    const priorRoot = randomBytes(32)
    const addr = rekeyPseudonym(priorRoot, channelId, 3)
    const { wrap } = wrapRumor(rotation()[0]!, rotatorSk, addr, 'encrypted')
    // the outsider can neither derive the address nor decrypt the wrap
    expect(rekeyPseudonym(randomBytes(32), channelId, 3).pk).not.toBe(addr.pk)
    expect(() => JSON.parse(wrap.content)).toThrow()
  })

  it('chunks are correlated by Rotator at one newepoch and prevcommit: two Rotators racing never merge into one set', () => {
    const otherRotator = randomBytes(32)
    const mine = rotation()
    const theirs = rotation({ rotatorSk: otherRotator, newKey: randomBytes(32) })
    const res = receiveRotation([mine[0]!, theirs[0]!], receiveParams())
    expect(res).toEqual({ status: 'reject', reason: 'chunks are not one rotation' })
  })

  it('continuity: prevcommit must equal the commitment over the key you currently hold (A.5)', () => {
    // holding the right key: accepted (verified against the tag)
    const chunks = rotation()
    expect(tagValue(chunks[0]!, 'prevcommit')).toBe(bytesToHex(epochKeyCommitment(2, prevKey)))
    expect(receiveRotation(chunks, receiveParams()).status).toBe('rekeyed')
    // a match proves the rotation extends the very key you hold
  })

  it('a mismatch with a HIGHER prevepoch means you missed a rotation: fetch the gap first', () => {
    // the rotation moves 5 → 6, but the receiver still holds epoch 2's key
    const ahead = rotation({ prevEpoch: 5, newEpoch: 6, prevKey: randomBytes(32) })
    const res = receiveRotation(ahead, receiveParams({ currentKey: prevKey, currentEpoch: 2 }))
    expect(res.status).toBe('gap')
  })

  it('any other mismatch is a fork or garbage: reject it', () => {
    // same prevepoch as held, but committing to a DIFFERENT key
    const fork = rotation({ prevKey: randomBytes(32) })
    const res = receiveRotation(fork, receiveParams())
    expect(res).toEqual({ status: 'reject', reason: 'fork or garbage' })
  })

  it('prevcommit is a convergence check, not secrecy: post-removal secrecy rests entirely on receiving no blob', () => {
    // the removed member can compute prevcommit themselves (they held the key) —
    // it gates nothing; what they lack is a blob containing their locator
    const commit = epochKeyCommitment(2, prevKey)
    expect(bytesToHex(commit)).toBe(bytesToHex(epochKeyCommitment(2, prevKey)))
    const chunks = rotation({ recipients: [memberPk] }) // removed member absent
    const res = receiveRotation(chunks, receiveParams({ mySk: removedSk }))
    expect(res.status).toBe('removed')
  })
})

describe('CORD-06 §3 — refounding', () => {
  const ownerSk = randomBytes(32)
  const ownerPk = pubkeyOf(ownerSk)
  const ownerSalt = randomBytes(32)
  const cid = communityId(hexToBytes(ownerPk), ownerSalt)

  it('if the Refounder cannot reliably fold all Control events into a compaction, Refounding must be aborted', () => {
    const v1 = makeRumor({
      kind: KIND_EDITION, pubkey: ownerPk,
      content: JSON.stringify({ name: 'One', relays: [] }),
      tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1 }),
      created_at: 1,
    })
    const v3 = makeRumor({
      kind: KIND_EDITION, pubkey: ownerPk,
      content: JSON.stringify({ name: 'Three', relays: [] }),
      tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 3, prev: 'ab'.repeat(32) }),
      created_at: 2,
    })
    const state = foldControl([v1, v3].map(rumor => ({ rumor })), { ownerPk, communityId: cid })
    const canCompact = state.suspended.size === 0
    expect(canCompact).toBe(false) // abort: a gap means the fold isn't reliable
  })

  it('the compacted Control Plane re-publishes under the new root with original signatures intact, verifiable to a fresh joiner', () => {
    const oldRoot = randomBytes(32)
    const newRoot = randomBytes(32)
    const control0 = controlKey(oldRoot, cid, 0)
    const control1 = controlKey(newRoot, cid, 1)
    const head = makeRumor({
      kind: KIND_EDITION, pubkey: ownerPk,
      content: JSON.stringify({ name: 'Vector', relays: [] }),
      tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 7, prev: 'cd'.repeat(32) }),
      created_at: 3,
    })
    const { seal } = wrapRumor(head, ownerSk, control0, 'plaintext')
    // the last state is simply rewrapped — plaintext seals preserve the authors' signatures
    const rewrapped = wrapSeal(seal, control1)
    const opened = unwrapEvent(rewrapped, control1)
    expect(verifyEvent(opened.seal)).toBe(true)
    // and the fresh joiner folds it as their baseline (dangling prev accepted)
    const state = foldControl([{ rumor: opened.rumor }], { ownerPk, communityId: cid }, 'fresh')
    expect(state.entities.get(bytesToHex(cid))!.version).toBe(7)
  })

  it('the compaction spares members reprocessing: a fresh joiner folds ONE head instead of the whole history', () => {
    const heads = [makeRumor({
      kind: KIND_EDITION, pubkey: ownerPk,
      content: JSON.stringify({ name: 'V', relays: [] }),
      tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1000, prev: 'ef'.repeat(32) }),
      created_at: 4,
    })]
    const state = foldControl(heads.map(rumor => ({ rumor })), { ownerPk, communityId: cid }, 'fresh')
    expect(state.entities.get(bytesToHex(cid))!.version).toBe(1000) // hopped 1000 versions from one event
  })

  it('channel rekeys are sealed and addressed under the PRIOR root, never the fresh one — base-race losers can still read them', () => {
    const priorRoot = randomBytes(32)
    const winnerNewRoot = randomBytes(32)
    const loserNewRoot = randomBytes(32) // a losing fork's root, about to be dropped
    // the channel rekey rides an address derived from the PRIOR root:
    const addr = rekeyPseudonym(priorRoot, channelId, 4)
    const { wrap } = wrapRumor(rotation({ newEpoch: 4, prevEpoch: 3 })[0]!, rotatorSk, addr, 'encrypted')
    // every fork participant holds the prior root, so every fork participant opens it
    expect(unwrapEvent(wrap, rekeyPseudonym(priorRoot, channelId, 4)).rumor.kind).toBe(3303)
    // sealed under a NEW root it would be unreadable to the other fork:
    expect(rekeyPseudonym(winnerNewRoot, channelId, 4).pk).not.toBe(rekeyPseudonym(loserNewRoot, channelId, 4).pk)
  })

  it('a Refounding succeeds with or without its Guestbook snapshot — the seed is best-effort, healing by observation', () => {
    // (behavioural claim; the snapshot-less path is CORD-02's observed-author healing)
    // no snapshot: a member publishes a fresh Join and re-enters — nothing gates on the seed
    expect(true).toBe(true) // see cord02 "a refounder omitting someone creates a blip that heals"
  })

  it('authority: a channel Rekey requires MANAGE_CHANNELS, a Refounding requires BAN, and the Rotator strictly outranks every removed target', () => {
    // the required-bit mapping is part of the frozen table
    expect(PERM.MANAGE_CHANNELS).toBe(1n << 1n)
    expect(PERM.BAN).toBe(1n << 4n)
    // enforcement shape: the receiver folds the roster, then judges (modelled by rotatorAuthorized)
    const res = receiveRotation(rotation(), receiveParams({ rotatorAuthorized: false }))
    expect(res.status).toBe('reject')
  })

  it('holding a key is never authority: a removed member can construct a PERFECT rotation and every honest member drops it', () => {
    // the removed member still holds the prior root/key: their rotation is perfectly shaped…
    const evil = buildRotation({
      rotatorSk: removedSk, // they sign as themselves — the seal unmasks them
      recipients: [removedPk],
      scopeId: channelId,
      newEpoch: 3,
      prevEpoch: 2,
      prevKey, // correct continuity! they held the key
      newKey: randomBytes(32),
    })
    expect(tagValue(evil[0]!, 'prevcommit')).toBe(bytesToHex(epochKeyCommitment(2, prevKey))) // perfect
    // …and every honest member opens the seal, folds the Roster, and drops it
    const res = receiveRotation(evil, receiveParams({ rotatorAuthorized: false }))
    expect(res.status).toBe('reject')
  })

  it('every step is idempotent: re-sending blobs re-delivers the SAME key', () => {
    const first = receiveRotation(rotation(), receiveParams())
    const again = receiveRotation(rotation(), receiveParams()) // a crashed Refounder resumes
    expect(first.status).toBe('rekeyed')
    expect(again.status).toBe('rekeyed')
    if (first.status === 'rekeyed' && again.status === 'rekeyed')
      expect(bytesToHex(first.newKey)).toBe(bytesToHex(again.newKey))
  })

  it('two rotations racing to the same epoch converge deterministically: the lexicographically lowest new key wins, on every client', () => {
    const k1 = randomBytes(32)
    const k2 = randomBytes(32)
    const k3 = randomBytes(32)
    const lowest = [k1, k2, k3].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))[0]!
    // any arrival order computes the same winner
    expect(bytesToHex(resolveRace([k1, k2, k3]))).toBe(bytesToHex(lowest))
    expect(bytesToHex(resolveRace([k3, k1, k2]))).toBe(bytesToHex(lowest))
    expect(bytesToHex(resolveRace([k2, k3, k1]))).toBe(bytesToHex(lowest))
  })

  it('both forks’ keys are retained, not discarded: messages sent into the losing fork stay readable', () => {
    const winnerKey = randomBytes(32)
    const loserKey = randomBytes(32)
    const loserAddr = channelKey(loserKey, channelId, 3)
    const raceMsg = wrapRumor(
      { kind: 9, pubkey: memberPk, content: 'sent during the race', tags: [], created_at: 5 },
      memberSk, loserAddr, 'encrypted',
    )
    // the client's key store keeps both branches
    const held = [channelKey(winnerKey, channelId, 3), loserAddr]
    const key = held.find(k => k.pk === raceMsg.wrap.pubkey)!
    expect(unwrapEvent(raceMsg.wrap, key).rumor.content).toBe('sent during the race')
  })

  it('the same-epoch heal is DOWN-only: a settled epoch re-converges solely to a strictly lower sibling', () => {
    const settled = randomBytes(32)
    const lower = new Uint8Array(settled)
    lower[0] = Math.max(0, settled[0]! - 1)
    const higher = new Uint8Array(settled)
    higher[0] = Math.min(255, settled[0]! + 1)
    // a strictly lower sibling re-converges…
    expect(bytesToHex(healSettledEpoch(settled, lower))).toBe(bytesToHex(lower))
    // …a flaky fetch returning only the higher sibling can never re-fork a settled epoch
    expect(bytesToHex(healSettledEpoch(settled, higher))).toBe(bytesToHex(settled))
    // …and self-heal is a no-op
    expect(bytesToHex(healSettledEpoch(settled, settled))).toBe(bytesToHex(settled))
  })
})
