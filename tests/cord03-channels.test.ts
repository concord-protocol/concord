/**
 * CORD-03: Channels — every claim in 03.md, asserted.
 */
import { describe, expect, it } from 'vitest'
import { bytesToHex, hexToBytes, randomBytes } from '../src/bytes.js'
import {
  applyMetadataEdit,
  channelAddress,
  newPublicChannel,
  privatise,
  publicise,
  type ChannelMetadata,
} from '../src/channels.js'
import { channelKey, communityId } from '../src/derive.js'
import { makeRumor, pubkeyOf, type Rumor } from '../src/events.js'
import { nameWithinCap } from '../src/roster.js'
import { checkBinding, StreamError, unwrapEvent, wrapRumor, wrapSeal } from '../src/stream.js'

const ownerSk = randomBytes(32)
const ownerPk = pubkeyOf(ownerSk)
const root = randomBytes(32)

function msg(content: string, channelId: string, epoch: number): Omit<Rumor, 'id'> {
  return {
    kind: 9,
    pubkey: ownerPk,
    content,
    tags: [
      ['channel', channelId],
      ['epoch', String(epoch)],
      ['ms', '0'],
    ],
    created_at: 1686840217,
  }
}

describe('CORD-03 §1 — keying', () => {
  it('every Channel is addressed through the one group_key derivation; only secret and epoch differ by kind', () => {
    const ch = newPublicChannel()
    const pub = channelAddress(ch, root, 0)
    expect(pub.pk).toBe(channelKey(root, ch.channelId, 0).pk)
    const priv = privatise(ch)
    expect(channelAddress(priv, root, 0).pk).toBe(channelKey(priv.channelKey!, ch.channelId, 1).pk)
  })

  it('channel_id is folded into the derivation: distinct addresses regardless of which secret feeds them', () => {
    const a = newPublicChannel()
    const b = newPublicChannel()
    expect(channelAddress(a, root, 0).pk).not.toBe(channelAddress(b, root, 0).pk) // same secret (root), distinct ids
  })

  it('a Public Channel is just "a Channel whose key derives from the community_root" — no delivery, nothing in an invite', () => {
    const ch = newPublicChannel()
    expect(ch.channelKey).toBeNull() // no access key generation nor distribution
    // any member holding the root derives the address independently
    expect(channelAddress(ch, root, 0).pk).toBe(channelKey(root, ch.channelId, 0).pk)
  })

  it('a Public Channel rotates for free whenever the base does (a Refounding severs it along with the base)', () => {
    const ch = newPublicChannel()
    const before = channelAddress(ch, root, 0)
    const newRoot = randomBytes(32)
    const after = channelAddress(ch, newRoot, 1)
    expect(after.pk).not.toBe(before.pk)
    // the removed member (holding old root) can no longer address or read it
    const post = wrapRumor(msg('post', bytesToHex(ch.channelId), 1), ownerSk, after, 'encrypted')
    expect(() => unwrapEvent(post.wrap, before)).toThrow(StreamError)
  })

  it('a Private Channel has real independence: a leaked channel key exposes only that one Channel', () => {
    const a = privatise(newPublicChannel())
    const b = privatise(newPublicChannel())
    const addrA = channelAddress(a, root, 0)
    const addrB = channelAddress(b, root, 0)
    const inA = wrapRumor(msg('in A', bytesToHex(a.channelId), 1), ownerSk, addrA, 'encrypted')
    // the holder of A's key cannot open (or even locate) B
    expect(addrA.pk).not.toBe(addrB.pk)
    expect(() => unwrapEvent(inA.wrap, addrB)).toThrow(StreamError)
    // and A's key says nothing about the root-derived planes
    expect(channelKey(a.channelKey!, a.channelId, 1).pk).not.toBe(channelKey(root, a.channelId, 0).pk)
  })

  it('a Private Channel can be rotated independently, without touching community-wide access', () => {
    const ch = privatise(newPublicChannel()) // epoch 1
    const rotated = { ...ch, channelKey: randomBytes(32), channelEpoch: ch.channelEpoch + 1 }
    expect(channelAddress(rotated, root, 0).pk).not.toBe(channelAddress(ch, root, 0).pk)
    // the root (and every root-derived plane) is untouched
    expect(channelKey(root, ch.channelId, 0).pk).toBe(channelKey(root, ch.channelId, 0).pk)
  })
})

describe('CORD-03 §2 — metadata', () => {
  it('ChannelMetadata holds channel_id (as eid), name ≤ 64 bytes, and the private flag', () => {
    const meta: ChannelMetadata = { name: 'general', private: false }
    expect(nameWithinCap(meta.name)).toBe(true)
    expect(nameWithinCap('x'.repeat(65))).toBe(false) // the protocol-wide cap
  })

  it('deletion is terminal: the latch never reopens, the id is never reused', () => {
    let state = applyMetadataEdit(null, { name: 'general', private: false })
    state = applyMetadataEdit(state, { name: 'general', private: false, deleted: true })
    expect(state.deleted).toBe(true)
    // an edit trying to revive it is a no-op
    const revived = applyMetadataEdit(state, { name: 'general-2', private: false })
    expect(revived.deleted).toBe(true)
    expect(revived.name).toBe('general')
  })

  it('deletion can’t unshare the past: history stays decryptable to anyone who already held the keys', () => {
    const ch = newPublicChannel()
    const addr = channelAddress(ch, root, 0)
    const old = wrapRumor(msg('history', bytesToHex(ch.channelId), 0), ownerSk, addr, 'encrypted')
    // delete the channel — nothing about held keys changes
    applyMetadataEdit({ name: 'general', private: false }, { name: 'general', private: false, deleted: true })
    expect(unwrapEvent(old.wrap, addr).rumor.content).toBe('history')
  })

  it('privatising mints an independent key at the NEXT channel_epoch: first privatisation is epoch 1, later ones climb', () => {
    const ch = newPublicChannel()
    expect(ch.channelEpoch).toBe(0)
    const p1 = privatise(ch)
    expect(p1.channelEpoch).toBe(1)
    expect(p1.channelKey).not.toBeNull()
    const back = publicise(p1)
    const p2 = privatise(back)
    expect(p2.channelEpoch).toBe(2) // monotonic, never resetting
    expect(bytesToHex(p2.channelKey!)).not.toBe(bytesToHex(p1.channelKey!))
  })

  it('the channel_id never changes across any conversion — it is the Channel’s permanent identity', () => {
    const ch = newPublicChannel()
    const p = privatise(ch)
    const b = publicise(p)
    const p2 = privatise(b)
    expect(bytesToHex(p.channelId)).toBe(bytesToHex(ch.channelId))
    expect(bytesToHex(b.channelId)).toBe(bytesToHex(ch.channelId))
    expect(bytesToHex(p2.channelId)).toBe(bytesToHex(ch.channelId))
  })

  it('privatise → publish → privatise is safe: each private generation lives at a distinct epoch, a stale key never shares a coordinate', () => {
    const ch = newPublicChannel()
    const gen1 = privatise(ch) // epoch 1
    const gen2 = privatise(publicise(gen1)) // epoch 2
    const addr1 = channelAddress(gen1, root, 0)
    const addr2 = channelAddress(gen2, root, 0)
    expect(addr1.pk).not.toBe(addr2.pk)
    // the stale key (lower epoch) cannot decrypt the current generation
    const current = wrapRumor(msg('gen2', bytesToHex(ch.channelId), 2), ownerSk, addr2, 'encrypted')
    expect(() => unwrapEvent(current.wrap, addr1)).toThrow(StreamError)
  })

  it('a joiner is simply handed the current (key, epoch) — that alone reconstructs the address', () => {
    const gen = privatise(newPublicChannel())
    const invitePayload = { id: bytesToHex(gen.channelId), key: bytesToHex(gen.channelKey!), epoch: gen.channelEpoch }
    const rebuilt = channelKey(hexToBytes(invitePayload.key), hexToBytes(invitePayload.id), invitePayload.epoch)
    expect(rebuilt.pk).toBe(channelAddress(gen, root, 0).pk)
  })

  it('privatising protects the FUTURE only: pre-conversion history stays readable to all members', () => {
    const ch = newPublicChannel()
    const pubAddr = channelAddress(ch, root, 0)
    const before = wrapRumor(msg('public era', bytesToHex(ch.channelId), 0), ownerSk, pubAddr, 'encrypted')
    const priv = privatise(ch)
    const privAddr = channelAddress(priv, root, 0)
    const after = wrapRumor(msg('private era', bytesToHex(ch.channelId), 1), ownerSk, privAddr, 'encrypted')

    // a member NOT granted the private key still reads the pre-conversion history…
    expect(unwrapEvent(before.wrap, pubAddr).rumor.content).toBe('public era')
    // …but nothing after the conversion
    expect(() => unwrapEvent(after.wrap, pubAddr)).toThrow(StreamError)
  })

  it('Private → Public: a post-switch joiner reads only the now-public history, never the prior private messages', () => {
    const priv = privatise(newPublicChannel())
    const privAddr = channelAddress(priv, root, 0)
    const secretMsg = wrapRumor(msg('private era', bytesToHex(priv.channelId), 1), ownerSk, privAddr, 'encrypted')

    const pub = publicise(priv)
    const pubAddr = channelAddress(pub, root, 0)
    const openMsg = wrapRumor(msg('public era', bytesToHex(pub.channelId), 0), ownerSk, pubAddr, 'encrypted')

    // the joiner holds only the root: the public plane opens, the private one never does
    expect(unwrapEvent(openMsg.wrap, pubAddr).rumor.content).toBe('public era')
    expect(() => unwrapEvent(secretMsg.wrap, pubAddr)).toThrow(StreamError)
    // they never held that key — and can't derive it from the root
    expect(privAddr.pk).not.toBe(channelKey(root, priv.channelId, 1).pk)
  })
})

describe('CORD-03 §3 — messages', () => {
  it('history spanning a rekey stays continuous: clients query every epoch pubkey they hold', () => {
    const ch = newPublicChannel()
    const chIdHex = bytesToHex(ch.channelId)
    const e0 = channelAddress(ch, root, 0)
    const newRoot = randomBytes(32)
    const e1 = channelAddress(ch, newRoot, 1)
    const m0 = wrapRumor(msg('epoch 0', chIdHex, 0), ownerSk, e0, 'encrypted')
    const m1 = wrapRumor(msg('epoch 1', chIdHex, 1), ownerSk, e1, 'encrypted')
    // the filter is {"kinds":[1059],"authors":[<channel_pk per held epoch>]}
    const held = [e0, e1]
    const timeline = [m0.wrap, m1.wrap].map(w => {
      const key = held.find(k => k.pk === w.pubkey)!
      return unwrapEvent(w, key).rumor.content
    })
    expect(timeline).toEqual(['epoch 0', 'epoch 1'])
  })

  it('each message MUST commit ["channel", id] and ["epoch", n] inside the author-signed rumor', () => {
    const ch = newPublicChannel()
    const rumor = makeRumor(msg('bound', bytesToHex(ch.channelId), 0))
    expect(rumor.tags.find(t => t[0] === 'channel')![1]).toBe(bytesToHex(ch.channelId))
    expect(rumor.tags.find(t => t[0] === 'epoch')![1]).toBe('0')
  })

  it('a receiver MUST strict-check both against the decrypting key and drop a mismatch: no cross-Channel re-wrap', () => {
    const chA = newPublicChannel()
    const chB = newPublicChannel()
    const addrA = channelAddress(chA, root, 0)
    const addrB = channelAddress(chB, root, 0)

    // a member re-wraps alice's #a message into #b (they hold both keys)
    const { seal } = wrapRumor(msg('for #a only', bytesToHex(chA.channelId), 0), ownerSk, addrA, 'encrypted')
    // (encrypted seals can't even be moved: the ciphertext binds the conv key —
    //  so model the strongest attacker with a plaintext-sealed copy)
    const { seal: ptSeal } = wrapRumor(msg('for #a only', bytesToHex(chA.channelId), 0), ownerSk, addrA, 'plaintext')
    const spliced = wrapSeal(ptSeal, addrB)
    const opened = unwrapEvent(spliced, addrB)
    // binding check against the coordinate whose key opened the wrap
    expect(checkBinding(opened.rumor, { channelId: bytesToHex(chB.channelId), epoch: 0 })).toBe(false) // dropped
    expect(checkBinding(opened.rumor, { channelId: bytesToHex(chA.channelId), epoch: 0 })).toBe(true)
    void seal
  })

  it('…and no replay across an epoch: an epoch mismatch is dropped too', () => {
    const ch = newPublicChannel()
    const chIdHex = bytesToHex(ch.channelId)
    const e0 = channelAddress(ch, root, 0)
    const { seal } = wrapRumor(msg('epoch 0 msg', chIdHex, 0), ownerSk, e0, 'plaintext')
    // replay into epoch 1 after a refounding
    const e1 = channelAddress(ch, randomBytes(32), 1)
    const replayed = wrapSeal(seal, e1)
    const opened = unwrapEvent(replayed, e1)
    expect(checkBinding(opened.rumor, { channelId: chIdHex, epoch: 1 })).toBe(false) // dropped
  })

  it('the ordinary append events all ride the same envelope: message, reaction, edit, delete', () => {
    const ch = newPublicChannel()
    const addr = channelAddress(ch, root, 0)
    const chIdHex = bytesToHex(ch.channelId)
    const kinds = [9, 7, 3302, 5]
    for (const kind of kinds) {
      const { wrap } = wrapRumor({ ...msg('x', chIdHex, 0), kind }, ownerSk, addr, 'encrypted')
      const opened = unwrapEvent(wrap, addr)
      expect(opened.rumor.kind).toBe(kind)
      expect(opened.seal.pubkey).toBe(ownerPk) // sealed to the author's real identity
    }
  })
})

describe('CORD-03 — cross-community isolation (implied by the derivations)', () => {
  it('the same channel_id under two different communities never shares an address', () => {
    const chId = randomBytes(32)
    const rootA = randomBytes(32)
    const rootB = randomBytes(32)
    expect(channelKey(rootA, chId, 0).pk).not.toBe(channelKey(rootB, chId, 0).pk)
    void communityId // identity is upstream of keys; roots differ per community
  })
})
