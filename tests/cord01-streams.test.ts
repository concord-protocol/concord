/**
 * CORD-01: Private Streams — every claim in 01.md, asserted.
 * Each test names the claim it evidences.
 */
import { describe, expect, it } from 'vitest'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { schnorr } from '@noble/curves/secp256k1'
import { bytesToHex, randomBytes } from '../src/bytes.js'
import { groupKey } from '../src/derive.js'
import { makeRumor, pubkeyOf, verifyEvent, type Rumor, type SignedEvent } from '../src/events.js'
import {
  checkBinding,
  KIND_SEAL_ENCRYPTED,
  KIND_SEAL_PLAINTEXT,
  makeSeal,
  unwrapEvent,
  wrapRumor,
  wrapSeal,
  StreamError,
} from '../src/stream.js'

/** A private stream is simply a shared secret; derive a keypair from it. */
function newStream(secret = randomBytes(32)) {
  return groupKey('concord/test-stream', secret)
}

const alice = randomBytes(32)
const alicePk = pubkeyOf(alice)

function chatRumor(content: string, tags: string[][] = []): Omit<Rumor, 'id'> {
  return { kind: 9, pubkey: alicePk, content, tags, created_at: 1686840217 }
}

describe('CORD-01 — the stream event', () => {
  it('participants sign kind 1059 wraps with the shared key; the stream is queryable by {"kinds":[1059],"authors":[stream pk]}', () => {
    const stream = newStream()
    const { wrap } = wrapRumor(chatRumor('Hey chat!'), alice, stream, 'encrypted')
    // matches the filter the spec gives
    expect(wrap.kind).toBe(1059)
    expect(wrap.pubkey).toBe(stream.pk)
    expect(verifyEvent(wrap)).toBe(true) // signed by the shared stream key
  })

  it('any keyholder can read the stream (roundtrip through wrap → seal → rumor)', () => {
    const stream = newStream()
    const { rumor, wrap } = wrapRumor(chatRumor('Hey chat!'), alice, stream, 'encrypted')
    const opened = unwrapEvent(wrap, stream)
    expect(opened.rumor).toEqual(rumor)
    expect(opened.rumor.content).toBe('Hey chat!')
    expect(opened.rumor.pubkey).toBe(alicePk) // the real author, sealed within
  })

  it('a non-keyholder cannot decrypt the wrap', () => {
    const stream = newStream()
    const { wrap } = wrapRumor(chatRumor('secret'), alice, stream, 'encrypted')
    const outsider = newStream(randomBytes(32))
    // wrong conv key: decryption fails
    expect(() => nip44.decrypt(wrap.content, outsider.convKey)).toThrow()
  })

  it('a non-keyholder cannot even identify the stream address (address derives from the secret)', () => {
    const secret = randomBytes(32)
    const a = groupKey('concord/test-stream', secret)
    const b = groupKey('concord/test-stream', randomBytes(32)) // outsider's guess
    expect(b.pk).not.toBe(a.pk)
  })

  it('blends with giftwrap traffic: kind 1059, one "p" tag, opaque content, no protocol markers', () => {
    const stream = newStream()
    const { wrap } = wrapRumor(chatRumor('Hey chat!'), alice, stream, 'encrypted')
    expect(wrap.kind).toBe(1059)
    expect(wrap.tags).toHaveLength(1)
    expect(wrap.tags[0]![0]).toBe('p')
    // CORD-02 Appendix B: no version tag anywhere — it would unmask the camouflage
    expect(wrap.tags.every(t => t[0] === 'p')).toBe(true)
    expect(() => JSON.parse(wrap.content)).toThrow() // content is ciphertext, not readable JSON
  })
})

describe('CORD-01 — inversions vs NIP-59', () => {
  it('fixed author + ephemeral "p" tag (reversed from NIP-59)', () => {
    const stream = newStream()
    const w1 = wrapRumor(chatRumor('one'), alice, stream, 'encrypted').wrap
    const w2 = wrapRumor(chatRumor('two'), alice, stream, 'encrypted').wrap
    expect(w1.pubkey).toBe(w2.pubkey) // fixed author: the stream pubkey
    expect(w1.tags[0]![1]).not.toBe(w2.tags[0]![1]) // ephemeral p, fresh per event
  })

  it('the wrap is encrypted under the stream conversation key (self-ECDH), never the p-tagged key', () => {
    const stream = newStream()
    const pSk = randomBytes(32)
    const pPk = pubkeyOf(pSk)
    const rumor = makeRumor(chatRumor('hi'))
    const seal = makeSeal(rumor, alice, 'encrypted', stream.convKey)
    const wrap = wrapSeal(seal, stream, { ephemeralPubkey: pPk })

    // the stream conv key opens it…
    expect(() => nip44.decrypt(wrap.content, stream.convKey)).not.toThrow()
    // …the p-tagged key does not (in NIP-59 it would)
    const pConv = nip44.utils.getConversationKey(pSk, wrap.pubkey)
    expect(() => nip44.decrypt(wrap.content, pConv)).toThrow()
  })

  it('the self-ECDH conversation key is exactly nip44_conversation_key(sk, pk) of the stream key', () => {
    const stream = newStream()
    const skHex = bytesToHex(schnorr.getPublicKey(stream.sk))
    expect(skHex).toBe(stream.pk)
    expect(bytesToHex(stream.convKey)).toBe(
      bytesToHex(nip44.utils.getConversationKey(stream.sk, stream.pk)),
    )
  })

  it('the seal kind is 20013 (encrypted) or 20014 (plaintext), never kind 13', () => {
    const stream = newStream()
    const enc = wrapRumor(chatRumor('a'), alice, stream, 'encrypted').seal
    const pt = wrapRumor(chatRumor('b'), alice, stream, 'plaintext').seal
    expect(enc.kind).toBe(20013)
    expect(pt.kind).toBe(20014)
    expect(KIND_SEAL_ENCRYPTED).not.toBe(13)
    expect(KIND_SEAL_PLAINTEXT).not.toBe(13)
  })

  it('created_at is not altered or tweaked', () => {
    const stream = newStream()
    const { rumor, seal, wrap } = wrapRumor(chatRumor('t'), alice, stream, 'encrypted')
    expect(seal.created_at).toBe(rumor.created_at)
    expect(wrap.created_at).toBe(rumor.created_at)
  })
})

describe('CORD-01 — seal content, encrypted or plaintext', () => {
  it('an encrypted seal is a non-standalone artifact: its content is ciphertext no relay can display', () => {
    const stream = newStream()
    const { seal } = wrapRumor(chatRumor('leak-resistant'), alice, stream, 'encrypted')
    expect(() => JSON.parse(seal.content)).toThrow() // nothing standalone to lift
    // only a keyholder recovers the rumor from the seal
    const rumor = JSON.parse(nip44.decrypt(seal.content, stream.convKey))
    expect(rumor.content).toBe('leak-resistant')
  })

  it('a plaintext seal carries a signed rumor that survives re-wrapping across a key rotation', () => {
    const oldStream = newStream()
    const { seal } = wrapRumor(chatRumor('durable'), alice, oldStream, 'plaintext')

    // key rotation: re-wrap the SAME signed seal under a new stream key
    const newStream_ = newStream(randomBytes(32))
    const rewrapped = wrapSeal(seal, newStream_)
    const opened = unwrapEvent(rewrapped, newStream_)
    expect(opened.seal.sig).toBe(seal.sig) // the signature survived verbatim
    expect(verifyEvent(opened.seal)).toBe(true)
    expect(opened.rumor.content).toBe('durable')
  })

  it('a signature over encrypted content is bound to the encrypting key and breaks under re-encryption', () => {
    const oldStream = newStream()
    const rumor = makeRumor(chatRumor('bound'))
    const seal = makeSeal(rumor, alice, 'encrypted', oldStream.convKey)

    // naive rotation: decrypt the rumor and re-encrypt under the new key —
    // the old signature no longer covers the new content
    const newStream_ = newStream(randomBytes(32))
    const reEncrypted: SignedEvent = {
      ...seal,
      content: nip44.encrypt(JSON.stringify(rumor), newStream_.convKey),
    }
    expect(verifyEvent(reEncrypted)).toBe(false)
  })

  it("the seal's kind declares its form — a reader never sniffs the content", () => {
    const stream = newStream()
    const enc = wrapRumor(chatRumor('x'), alice, stream, 'encrypted')
    const pt = wrapRumor(chatRumor('y'), alice, stream, 'plaintext')
    expect(unwrapEvent(enc.wrap, stream).form).toBe('encrypted')
    expect(unwrapEvent(pt.wrap, stream).form).toBe('plaintext')
    // an unexpected seal kind is an error, not a guess
    const badSeal = { ...enc.seal, kind: 13 }
    const badWrap = wrapSeal(badSeal as SignedEvent, stream)
    expect(() => unwrapEvent(badWrap, stream)).toThrow(StreamError)
  })

  it('a forged seal (signature not by the claimed author) is rejected', () => {
    const stream = newStream()
    const mallory = randomBytes(32)
    const rumor = makeRumor(chatRumor('forged'))
    // mallory signs but claims alice's pubkey
    const forged = makeSeal(rumor, mallory, 'encrypted', stream.convKey)
    const lying: SignedEvent = { ...forged, pubkey: alicePk }
    const wrap = wrapSeal(lying, stream)
    expect(() => unwrapEvent(wrap, stream)).toThrow(StreamError)
  })

  it('a rumor whose author differs from the seal author is rejected', () => {
    const stream = newStream()
    const mallory = randomBytes(32)
    // mallory seals (validly, as themselves) a rumor claiming alice authored it
    const rumor = makeRumor({ ...chatRumor('impersonation'), pubkey: alicePk })
    const seal = makeSeal(rumor, mallory, 'encrypted', stream.convKey)
    const wrap = wrapSeal(seal, stream)
    expect(() => unwrapEvent(wrap, stream)).toThrow(/author/)
  })
})

describe('CORD-01 — binding', () => {
  it("any keyholder CAN re-publish a decrypted seal at another stream address — the author's signature proves who, not context", () => {
    const streamA = newStream()
    const streamB = newStream(randomBytes(32))
    const { seal } = wrapRumor(chatRumor('spliceable'), alice, streamA, 'plaintext')

    // a keyholder of both lifts the seal from A and republishes at B
    const spliced = wrapSeal(seal, streamB)
    const opened = unwrapEvent(spliced, streamB)
    // the splice "succeeds" mechanically: signature still valid, author proven
    expect(verifyEvent(opened.seal)).toBe(true)
    expect(opened.rumor.pubkey).toBe(alicePk)
  })

  it('committing context tags inside the signed rumor and checking them against the decrypting coordinate defeats the splice', () => {
    const ctxA = { channelId: 'aa'.repeat(32), epoch: 0 }
    const ctxB = { channelId: 'bb'.repeat(32), epoch: 0 }
    const streamA = newStream()
    const streamB = newStream(randomBytes(32))

    const bound = chatRumor('bound to A', [
      ['channel', ctxA.channelId],
      ['epoch', '0'],
    ])
    const { seal } = wrapRumor(bound, alice, streamA, 'plaintext')

    // splice into B: the rumor still opens, but the committed context mismatches
    const spliced = wrapSeal(seal, streamB)
    const opened = unwrapEvent(spliced, streamB)
    expect(checkBinding(opened.rumor, ctxA)).toBe(true) // honest context
    expect(checkBinding(opened.rumor, ctxB)).toBe(false) // spliced context → dropped
  })

  it('a rumor cannot be spliced into a context the author never chose: tags are inside the signature', () => {
    const stream = newStream()
    const bound = chatRumor('mine', [
      ['channel', 'aa'.repeat(32)],
      ['epoch', '0'],
    ])
    const { rumor, seal } = wrapRumor(bound, alice, stream, 'plaintext')
    // tampering with the committed tags breaks the id/signature
    const tampered: Rumor = { ...rumor, tags: [['channel', 'bb'.repeat(32)], ['epoch', '0']] }
    const resealed: SignedEvent = { ...seal, content: JSON.stringify(tampered) }
    expect(verifyEvent(resealed)).toBe(false)
  })
})

describe('CORD-01 — deletions', () => {
  // A minimal relay model: the policy the spec asks relays to implement.
  type StoredWrap = SignedEvent
  function relayAcceptsDeletion(
    store: StoredWrap[],
    deletion: { requesterPk: string; targetWrapId: string },
    policy: 'reject-author-deletes' | 'nip59',
  ): boolean {
    const target = store.find(w => w.id === deletion.targetWrapId)
    if (!target) return false
    const pTag = target.tags.find(t => t[0] === 'p')?.[1]
    if (deletion.requesterPk === pTag) return true // NIP-59: p-tagged user owns the giftwrap
    if (deletion.requesterPk === target.pubkey)
      return policy === 'nip59' ? false : false // by author: rejected under both readings
    return false
  }

  it('relays should prevent giftwrap deletions by author — participants cannot delete each other’s wraps', () => {
    const stream = newStream()
    const { wrap } = wrapRumor(chatRumor('hi'), alice, stream, 'encrypted')
    const store = [wrap]
    // every participant signs with the SAME stream key (the wrap author), so an
    // author-delete would let any member erase any other member's events
    expect(
      relayAcceptsDeletion(store, { requesterPk: stream.pk, targetWrapId: wrap.id }, 'reject-author-deletes'),
    ).toBe(false)
  })

  it('giftwraps are owned by the recipient: deletion by the "p"-tagged user is allowed (NIP-59 semantics)', () => {
    const stream = newStream()
    const ephemeralSk = randomBytes(32)
    const ephemeralPk = pubkeyOf(ephemeralSk)
    const rumor = makeRumor(chatRumor('mine'))
    const seal = makeSeal(rumor, alice, 'encrypted', stream.convKey)
    const wrap = wrapSeal(seal, stream, { ephemeralPubkey: ephemeralPk })
    const store = [wrap]
    // the client saved the ephemeral key → it can delete its own giftwrap by "p" tag
    expect(
      relayAcceptsDeletion(store, { requesterPk: ephemeralPk, targetWrapId: wrap.id }, 'reject-author-deletes'),
    ).toBe(true)
  })

  it('users delete their content via giftwrapped kind 5 deletion events sent to the stream', () => {
    const stream = newStream()
    const msg = wrapRumor(chatRumor('oops'), alice, stream, 'encrypted')
    const del = wrapRumor(
      {
        kind: 5,
        pubkey: alicePk,
        content: '',
        tags: [['e', msg.rumor.id]],
        created_at: 1686841000,
      },
      alice,
      stream,
      'encrypted',
    )
    const opened = unwrapEvent(del.wrap, stream)
    expect(opened.rumor.kind).toBe(5)
    expect(opened.rumor.pubkey).toBe(alicePk) // self-signed: deletes own content
    expect(opened.rumor.tags[0]![1]).toBe(msg.rumor.id)
  })
})

describe('CORD-01 — removing participants', () => {
  it('removal requires a new stream: the removed member cannot read (or find) the successor', () => {
    const oldSecret = randomBytes(32)
    const oldStream = groupKey('concord/test-stream', oldSecret)
    // remove bob: mint a fresh secret, shared with everyone but bob
    const newSecret = randomBytes(32)
    const newStream_ = groupKey('concord/test-stream', newSecret)

    expect(newStream_.pk).not.toBe(oldStream.pk) // a different address entirely
    const { wrap } = wrapRumor(chatRumor('post-removal'), alice, newStream_, 'encrypted')
    // bob (holding only the old key) can neither address nor decrypt it
    expect(() => unwrapEvent(wrap, oldStream)).toThrow(StreamError)
  })

  it('clients merge events from both the old and new streams into a single chatroom', () => {
    const s1 = newStream()
    const s2 = newStream(randomBytes(32))
    const m1 = wrapRumor(chatRumor('before'), alice, s1, 'encrypted')
    const m2 = wrapRumor({ ...chatRumor('after'), created_at: 1686840300 }, alice, s2, 'encrypted')
    const merged = [unwrapEvent(m1.wrap, s1).rumor, unwrapEvent(m2.wrap, s2).rumor].sort(
      (a, b) => a.created_at - b.created_at,
    )
    expect(merged.map(r => r.content)).toEqual(['before', 'after'])
  })
})
