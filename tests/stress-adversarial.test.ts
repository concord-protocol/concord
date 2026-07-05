/**
 * Stress: adversarial. Attacks the spec does NOT explicitly enumerate,
 * probing whether its stated mechanisms actually close them. Where a residual
 * risk is inherent to the design, the test documents it as such — this suite
 * is the canon of what an attacker can and cannot do.
 */
import { describe, expect, it } from 'vitest'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { bytesToHex, hexToBytes, randomBytes } from '../src/bytes.js'
import { communityId, groupKey, guestbookKey } from '../src/derive.js'
import {
  banlistEid,
  editionTags,
  foldControl,
  grantEid,
  KIND_EDITION,
  parseEdition,
  VSK,
  type FoldContext,
} from '../src/editions.js'
import { hasValidMs, makeRumor, pubkeyOf, signEvent, verifyEvent, type Rumor, type SignedEvent } from '../src/events.js'
import { foldGuestbook, KIND_JOIN_LEAVE } from '../src/guestbook.js'
import { decodeFragment, encodeFragment } from '../src/invites.js'
import { PERM, rank, RANK_ROLELESS, writePermissions, type Role } from '../src/roster.js'
import { makeSeal, unwrapEvent, wrapSeal, wrapRumor, StreamError } from '../src/stream.js'
import { prng, randomBytesSeeded } from './helpers/rand.js'

const ownerSk = randomBytes(32)
const ownerPk = pubkeyOf(ownerSk)
const ownerSalt = randomBytes(32)
const cid = communityId(hexToBytes(ownerPk), ownerSalt)
const ctx: FoldContext = { ownerPk, communityId: cid }
const root = randomBytes(32)

const aliceSk = randomBytes(32)
const alicePk = pubkeyOf(aliceSk)

function edition(e: {
  signer: string; vsk: number; eid: string; version: number
  prev?: string | null; vac?: { eid: string; version: number; hash: string } | null
  content: unknown
}): Rumor {
  return makeRumor({
    kind: KIND_EDITION,
    pubkey: e.signer,
    content: typeof e.content === 'string' ? e.content : JSON.stringify(e.content),
    tags: editionTags(e),
    created_at: 1686840217,
  })
}
const hashOf = (r: Rumor) => parseEdition(r).hash
const role = (id: string, position: number, perms: bigint): Role => ({
  role_id: id, name: 'r', position, permissions: writePermissions(perms), scope: { kind: 'server' }, color: 0,
})

describe('adversarial — millisecond-tag malleability (CORD-02 §4)', () => {
  it('an out-of-range ms tag cannot smuggle extra "future" past the one-hour clock check', () => {
    const NOW = 1_722_000_000_000
    const m = pubkeyOf(randomBytes(32))
    // created_at is within the window, but ms=999999 pushes msTime past it
    const smuggled = makeRumor({
      kind: KIND_JOIN_LEAVE, pubkey: m, content: 'join',
      tags: [['ms', '999999']], created_at: Math.floor(NOW / 1000) + 3000,
    })
    expect(hasValidMs(smuggled)).toBe(false)
    const fold = foldGuestbook([smuggled], { nowMs: NOW, kickAuthorized: () => true })
    expect(fold.members.has(m)).toBe(false) // dropped, not interpreted
  })

  it('negative, fractional, exponential, and non-numeric ms values are all malformed', () => {
    for (const bad of ['-1', '1.5', '1e2', 'NaN', '01x', '', '1000', '99999']) {
      const r = makeRumor({ kind: 3306, pubkey: alicePk, content: 'join', tags: [['ms', bad]], created_at: 1 })
      expect(hasValidMs(r), `ms=${JSON.stringify(bad)}`).toBe(false)
    }
    for (const good of ['0', '1', '999']) {
      const r = makeRumor({ kind: 3306, pubkey: alicePk, content: 'join', tags: [['ms', good]], created_at: 1 })
      expect(hasValidMs(r), `ms=${JSON.stringify(good)}`).toBe(true)
    }
  })

  it('DOCUMENTED RESIDUAL: the rumor id is content-derived, so an author can grind a low id to win their own ties', () => {
    // The tie-break "lower rumor id" is deliberately attacker-influenceable —
    // an author can mine tag/content variations until their id sorts first.
    const m = pubkeyOf(randomBytes(32))
    const t = 100
    const rival = makeRumor({ kind: KIND_JOIN_LEAVE, pubkey: m, content: 'leave', tags: [['ms', '5']], created_at: t })
    // grind: same npub, same msTime, vary an ignored tag until the id is lower
    let ground: Rumor | null = null
    for (let nonce = 0; nonce < 4096; nonce++) {
      const candidate = makeRumor({
        kind: KIND_JOIN_LEAVE, pubkey: m, content: 'join',
        tags: [['ms', '5'], ['x', String(nonce)]], created_at: t,
      })
      if (candidate.id < rival.id) { ground = candidate; break }
    }
    expect(ground).not.toBeNull() // grinding IS feasible…
    const fold = foldGuestbook([rival, ground!], { nowMs: 10_000_000, kickAuthorized: () => true })
    expect(fold.states.get(m)!.rumorId).toBe(ground!.id)
    // …but its blast radius is bounded: the Guestbook coalesces PER NPUB, so an
    // author only ever grinds ties against their own entries, and edition ties
    // are judged authority-first before the id is ever consulted (CORD-04 §1).
  })
})

describe('adversarial — forged authority citations (CORD-04 §5)', () => {
  function baseline() {
    const ADMIN = 'aa'.repeat(32)
    const adminRole = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: ADMIN, version: 1, content: role(ADMIN, 1, PERM.MANAGE_ROLES | PERM.BAN | PERM.MANAGE_METADATA) })
    const aliceGrant = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 1, content: { member: alicePk, role_ids: [ADMIN] } })
    return { adminRole, aliceGrant }
  }

  it('a vac citing the right version but a WRONG hash is a forgery (or a fork) and parks like an unsynced one', () => {
    const { adminRole, aliceGrant } = baseline()
    const forged = edition({
      signer: alicePk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1,
      vac: { eid: grantEid(cid, alicePk), version: 1, hash: 'ee'.repeat(32) }, // real version, fake hash
      content: { name: 'forged-citation', relays: [] },
    })
    const s = foldControl([adminRole, aliceGrant, forged].map(rumor => ({ rumor })), ctx)
    expect(s.entities.has(bytesToHex(cid))).toBe(false)
    // the honest citation folds
    const honest = edition({
      signer: alicePk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1,
      vac: { eid: grantEid(cid, alicePk), version: 1, hash: hashOf(aliceGrant) },
      content: { name: 'honest', relays: [] },
    })
    const s2 = foldControl([adminRole, aliceGrant, honest].map(rumor => ({ rumor })), ctx)
    expect(s2.entities.has(bytesToHex(cid))).toBe(true)
  })

  it('not even the OWNER can mint a Role at position 0: the top of the roster is not mintable', () => {
    // position 0 belongs to the owner alone ("never a Role"); a position-0 role
    // would create a permanent peer no one — including the owner — outranks
    const evil = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: 'bb'.repeat(32), version: 1, content: role('bb'.repeat(32), 0, PERM.BAN) })
    const s = foldControl([evil].map(rumor => ({ rumor })), ctx)
    expect(s.entities.has('bb'.repeat(32))).toBe(false)
    // negative and non-integer positions are malformed under any signer
    const negative = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: 'cc'.repeat(32), version: 1, content: role('cc'.repeat(32), -1, PERM.BAN) })
    const fractional = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: 'dd'.repeat(32), version: 1, content: role('dd'.repeat(32), 0.5, PERM.BAN) })
    const s2 = foldControl([negative, fractional].map(rumor => ({ rumor })), ctx)
    expect(s2.entities.size).toBe(0)
  })
})

describe('adversarial — cross-community and cross-epoch replay', () => {
  it('an owner-signed edition CANNOT be replayed into a sibling community: every derived coordinate binds the community_id', () => {
    // the same owner key runs two communities (different salts)
    const cidB = communityId(hexToBytes(ownerPk), randomBytes(32))
    const ctxB: FoldContext = { ownerPk, communityId: cidB }
    // an owner-signed banlist edition minted for community A…
    const banA = edition({ signer: ownerPk, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, content: [alicePk] })
    // …carried into community B's fold: its eid is A's banlist coordinate,
    // which is NOT B's banlist coordinate, so B's banlist stays empty
    const sB = foldControl([banA].map(rumor => ({ rumor })), ctxB)
    expect(banlistEid(cid)).not.toBe(banlistEid(cidB))
    expect(sB.banlist.size).toBe(0)
    // same for metadata (eid = the community_id itself) and grants
    expect(grantEid(cid, alicePk)).not.toBe(grantEid(cidB, alicePk))
  })

  it('a NON-owner edition replayed cross-community parks forever: its vac cites a grant coordinate the target community can never sync', () => {
    const ADMIN = 'aa'.repeat(32)
    const adminRole = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: ADMIN, version: 1, content: role(ADMIN, 1, PERM.MANAGE_ROLES | PERM.MANAGE_CHANNELS) })
    const aliceGrant = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 1, content: { member: alicePk, role_ids: [ADMIN] } })
    // alice's channel edit in community A cites her A-grant
    const chanEdit = edition({
      signer: alicePk, vsk: VSK.CHANNEL_METADATA, eid: 'ab'.repeat(32), version: 1,
      vac: { eid: grantEid(cid, alicePk), version: 1, hash: hashOf(aliceGrant) },
      content: { name: 'spliced', private: false },
    })
    // community B (same owner!) receives the splice — without A's grant edition,
    // the citation never resolves; and A's grant can't fold in B (wrong eid)
    const cidB = communityId(hexToBytes(ownerPk), randomBytes(32))
    const sB = foldControl([adminRole, chanEdit].map(rumor => ({ rumor })), { ownerPk, communityId: cidB })
    expect(sB.entities.has('ab'.repeat(32))).toBe(false)
    void aliceGrant
  })

  it('encrypted seals are replay-proof by construction: the signature binds ciphertext under the OLD conversation key', () => {
    // a guestbook Kick from epoch 0 cannot be re-sealed into epoch 1: the
    // attacker can decrypt the rumor (they hold epoch 0), but re-encrypting it
    // under epoch 1's conv key produces content the admin's signature no longer covers
    const gb0 = guestbookKey(root, cid, 0)
    const gb1 = guestbookKey(randomBytes(32), cid, 1)
    const kick = makeRumor({ kind: 3309, pubkey: ownerPk, content: '', tags: [['p', alicePk]], created_at: 100 })
    const seal0 = makeSeal(kick, ownerSk, 'encrypted', gb0.convKey)
    const resealed: SignedEvent = { ...seal0, content: nip44.encrypt(JSON.stringify(kick), gb1.convKey) }
    expect(verifyEvent(resealed)).toBe(false) // the replay dies at the seal
    // and carrying the epoch-0 seal verbatim doesn't decrypt under epoch 1
    const carried = wrapSeal(seal0, gb1)
    expect(() => unwrapEvent(carried, gb1)).toThrow(StreamError)
  })
})

describe('adversarial — malformed-input robustness (folds bound their own processing, CORD-02 §4)', () => {
  it('the control fold survives arbitrary garbage editions without crashing or folding any of it', () => {
    const rand = prng(0xdead)
    const garbage: Rumor[] = []
    for (let i = 0; i < 60; i++) {
      const tags: string[][] = []
      if (rand() > 0.3) tags.push(['vsk', String(Math.floor(rand() * 20) - 4)])
      if (rand() > 0.3) tags.push(['eid', rand() > 0.5 ? bytesToHex(randomBytesSeeded(rand)) : 'not-hex-at-all'])
      if (rand() > 0.3) tags.push(['ev', String(Math.floor(rand() * 10) - 3)])
      if (rand() > 0.6) tags.push(['ep', 'zz'])
      if (rand() > 0.6) tags.push(['vac', 'x'])
      garbage.push(makeRumor({
        kind: KIND_EDITION,
        pubkey: pubkeyOf(randomBytesSeeded(rand)),
        content: rand() > 0.5 ? '{{{{not json' : JSON.stringify({ position: 'NaN' }),
        tags,
        created_at: Math.floor(rand() * 1e9),
      }))
    }
    const honest = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'V', relays: [] } })
    const s = foldControl([...garbage, honest].map(rumor => ({ rumor })), ctx)
    expect(s.entities.size).toBe(1) // exactly the honest edition, nothing else
    expect(JSON.parse(s.entities.get(bytesToHex(cid))!.content).name).toBe('V')
  })

  it('the guestbook fold survives arbitrary garbage rumors', () => {
    const rand = prng(0xfeed)
    const garbage: Rumor[] = []
    for (let i = 0; i < 60; i++) {
      garbage.push(makeRumor({
        kind: [3306, 3309, 3312][Math.floor(rand() * 3)]!,
        pubkey: pubkeyOf(randomBytesSeeded(rand)),
        content: ['join', 'leave', 'JOIN ', '', 'not-a-verb', '[not json'][Math.floor(rand() * 6)]!,
        tags: rand() > 0.5 ? [['ms', String(Math.floor(rand() * 5000))]] : [],
        created_at: Math.floor(rand() * 2_000_000_000),
      }))
    }
    expect(() =>
      foldGuestbook(garbage, { nowMs: 1_722_000_000_000, kickAuthorized: () => true }),
    ).not.toThrow()
  })

  it('a wrap with a bit-flipped ciphertext is rejected cleanly, never half-processed', () => {
    const stream = groupKey('concord/test-stream', randomBytes(32))
    const { wrap } = wrapRumor(
      { kind: 9, pubkey: alicePk, content: 'x', tags: [], created_at: 1 },
      aliceSk, stream, 'encrypted',
    )
    for (const pos of [0, 10, wrap.content.length - 2]) {
      const flipped = { ...wrap, content: wrap.content.slice(0, pos) + (wrap.content[pos] === 'A' ? 'B' : 'A') + wrap.content.slice(pos + 1) }
      expect(() => unwrapEvent(flipped, stream)).toThrow(StreamError)
    }
  })

  it('a wrap whose decrypted payload is not a seal (or whose seal wraps junk) throws StreamError, not a raw parse error', () => {
    const stream = groupKey('concord/test-stream', randomBytes(32))
    const junkWrap = {
      ...wrapRumor({ kind: 9, pubkey: alicePk, content: 'x', tags: [], created_at: 1 }, aliceSk, stream, 'encrypted').wrap,
      content: nip44.encrypt('this is not a seal', stream.convKey),
    }
    // re-sign so only the payload is wrong
    const resigned = signEvent({ ...junkWrap }, stream.sk)
    expect(() => unwrapEvent(resigned, stream)).toThrow(StreamError)
  })

  it('the fragment decoder never mis-decodes: random or truncated bytes either throw or roundtrip exactly', () => {
    const rand = prng(0xf0f0)
    for (let i = 0; i < 300; i++) {
      const len = Math.floor(rand() * 60)
      const junk = Buffer.from(randomBytesSeeded(rand, len)).toString('base64url')
      let decoded: ReturnType<typeof decodeFragment> | null = null
      try {
        decoded = decodeFragment(junk)
      } catch {
        continue // clean rejection is fine
      }
      // if it decoded, it must be a well-formed fragment: 32-byte token, version ≥ 3
      expect(decoded.token).toHaveLength(32)
      expect(decoded.version).toBeGreaterThanOrEqual(3)
    }
    // truncated real fragments always throw
    const real = encodeFragment(randomBytes(32), 'stock')
    for (const cut of [1, 5, real.length - 4]) {
      expect(() => decodeFragment(real.slice(0, cut))).toThrow()
    }
  })

  it('a hostile Role with absurd numeric fields cannot poison rank arithmetic', () => {
    const ADMIN = 'aa'.repeat(32)
    const adminRole = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: ADMIN, version: 1, content: role(ADMIN, 1, PERM.MANAGE_ROLES) })
    const aliceGrant = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 1, content: { member: alicePk, role_ids: [ADMIN] } })
    // alice tries to mint roles with pathological positions
    const vac = { eid: grantEid(cid, alicePk), version: 1, hash: hashOf(aliceGrant) }
    const bads = [
      edition({ signer: alicePk, vsk: VSK.ROLE, eid: '11'.repeat(32), version: 1, vac, content: { ...role('11'.repeat(32), 2, 0n), position: Number.NaN } }),
      edition({ signer: alicePk, vsk: VSK.ROLE, eid: '22'.repeat(32), version: 1, vac, content: { ...role('22'.repeat(32), 2, 0n), position: Number.POSITIVE_INFINITY } }),
      edition({ signer: alicePk, vsk: VSK.ROLE, eid: '33'.repeat(32), version: 1, vac, content: '{"position": -0.0001}' }),
    ]
    const s = foldControl([adminRole, aliceGrant, ...bads].map(rumor => ({ rumor })), ctx)
    expect(s.entities.has('11'.repeat(32))).toBe(false)
    expect(s.entities.has('22'.repeat(32))).toBe(false)
    expect(s.entities.has('33'.repeat(32))).toBe(false)
    expect(rank(s.roster, pubkeyOf(randomBytes(32)))).toBe(RANK_ROLELESS) // arithmetic unpoisoned
  })
})
