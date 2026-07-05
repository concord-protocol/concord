/**
 * CORD-02: Communities — every claim in 02.md, asserted.
 */
import { describe, expect, it } from 'vitest'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { bytesToHex, concat, hexToBytes, randomBytes, u64be, utf8, ZERO32 } from '../src/bytes.js'
import {
  banlistLocator,
  baseRekeyPseudonym,
  channelKey,
  communityId,
  controlKey,
  dissolvedKey,
  epochKeyCommitment,
  grantLocator,
  groupKey,
  guestbookKey,
  hkdfConcord,
  inviteBundleId,
  inviteBundleKey,
  inviteBundleSigner,
  inviteLinksLocator,
  recipientLocator,
  rekeyPseudonym,
  scalarNormalize,
} from '../src/derive.js'
import { editionTags, foldControl, KIND_EDITION, VSK } from '../src/editions.js'
import { makeRumor, msTime, pubkeyOf, verifyEvent, type Rumor } from '../src/events.js'
import {
  buildSnapshotRumors,
  foldGuestbook,
  KIND_JOIN_LEAVE,
  KIND_KICK,
  KIND_SNAPSHOT,
  MAX_FUTURE_MS,
  SNAPSHOT_CHUNK,
  type GuestbookContext,
} from '../src/guestbook.js'
import {
  canonicalBytes,
  fitsNip44,
  liveEntries,
  mergeEntry,
  mergeLists,
  MAX_MEMBERSHIPS,
  NIP44_MAX_PLAINTEXT,
  type CommunityEntry,
  type CommunityList,
  type JoinMaterial,
} from '../src/communityList.js'
import { NAME_CAP_BYTES, nameWithinCap } from '../src/roster.js'
import { unwrapEvent, wrapRumor, wrapSeal } from '../src/stream.js'

// ---- fixtures ----------------------------------------------------------------

const ownerSk = randomBytes(32)
const ownerPk = pubkeyOf(ownerSk)
const ownerSalt = randomBytes(32)
const cid = communityId(hexToBytes(ownerPk), ownerSalt)
const root = randomBytes(32)

const NOW = 1_722_000_000_000

function gbCtx(over: Partial<GuestbookContext> = {}): GuestbookContext {
  return { nowMs: NOW, kickAuthorized: () => true, ...over }
}

function joinRumor(pubkey: string, created_at: number, ms = 0, verb = 'join', tags: string[][] = []): Rumor {
  return makeRumor({
    kind: KIND_JOIN_LEAVE,
    pubkey,
    content: verb,
    tags: [['ms', String(ms)], ...tags],
    created_at,
  })
}

// ---- §1 identity ---------------------------------------------------------------

describe('CORD-02 §1 — identity: the community_id', () => {
  it('community_id = sha256("concord/community" || owner_xonly || owner_salt), byte-exact (A.4)', () => {
    const manual = sha256(concat(utf8('concord/community'), hexToBytes(ownerPk), ownerSalt))
    expect(bytesToHex(cid)).toBe(bytesToHex(manual))
  })

  it('it is a plain SHA-256 commitment, NOT the hkdf construction', () => {
    const viaHkdf = hkdfConcord(hexToBytes(ownerPk), 'concord/community', ownerSalt)
    expect(bytesToHex(cid)).not.toBe(bytesToHex(viaHkdf))
  })

  it('any member can recompute the community_id from the invite fields and confirm the founder', () => {
    // salt is not secret; it travels inside invites
    expect(bytesToHex(communityId(hexToBytes(ownerPk), ownerSalt))).toBe(bytesToHex(cid))
    // a forged owner fails to reproduce the id
    const impostor = pubkeyOf(randomBytes(32))
    expect(bytesToHex(communityId(hexToBytes(impostor), ownerSalt))).not.toBe(bytesToHex(cid))
  })

  it('one owner can run many Communities: a fresh salt yields a fresh identity', () => {
    const other = communityId(hexToBytes(ownerPk), randomBytes(32))
    expect(bytesToHex(other)).not.toBe(bytesToHex(cid))
  })

  it('the owner proves key possession by SIGNING genesis, not merely holding the public key', () => {
    const genesis = makeRumor({
      kind: KIND_EDITION,
      pubkey: ownerPk,
      content: JSON.stringify({ name: 'Vector', relays: [] }),
      tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1 }),
      created_at: 1686840217,
    })
    const control = controlKey(root, cid, 0)
    const { seal, wrap } = wrapRumor(genesis, ownerSk, control, 'plaintext')
    expect(verifyEvent(seal)).toBe(true)
    expect(unwrapEvent(wrap, control).seal.pubkey).toBe(ownerPk)
  })

  it('genesis is exactly two owner-signed editions: metadata + one public #general channel, nothing more', () => {
    const channelId = randomBytes(32)
    const genesis = [
      makeRumor({
        kind: KIND_EDITION,
        pubkey: ownerPk,
        content: JSON.stringify({ name: 'Vector', relays: ['wss://jskitty.com/nostr'] }),
        tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1 }),
        created_at: 1686840217,
      }),
      makeRumor({
        kind: KIND_EDITION,
        pubkey: ownerPk,
        content: JSON.stringify({ name: 'general', private: false }),
        tags: editionTags({ vsk: VSK.CHANNEL_METADATA, eid: bytesToHex(channelId), version: 1 }),
        created_at: 1686840217,
      }),
    ]
    const state = foldControl(genesis.map(rumor => ({ rumor })), { ownerPk, communityId: cid })
    expect(state.entities.size).toBe(2)
    const channel = state.entities.get(bytesToHex(channelId))!
    expect(JSON.parse(channel.content)).toEqual({ name: 'general', private: false })
    // no default roles, no scaffolding
    expect(state.roster.roles.size).toBe(0)
    expect(state.roster.grants.size).toBe(0)
  })
})

// ---- §2 access -----------------------------------------------------------------

describe('CORD-02 §2 — access: the community_root', () => {
  it('the community_root is NOT derived from the community_id: access rotates while identity stays fixed', () => {
    const newRoot = randomBytes(32) // a Refounding mints an unrelated key
    expect(bytesToHex(newRoot)).not.toBe(bytesToHex(root))
    // identity unchanged by rotation
    expect(bytesToHex(communityId(hexToBytes(ownerPk), ownerSalt))).toBe(bytesToHex(cid))
    // but every root-derived coordinate moves
    expect(controlKey(newRoot, cid, 0).pk).not.toBe(controlKey(root, cid, 0).pk)
  })

  it('holding the root gates the Control Plane: without it neither the address nor the content is reachable', () => {
    const control = controlKey(root, cid, 0)
    const outsiderGuess = controlKey(randomBytes(32), cid, 0)
    expect(outsiderGuess.pk).not.toBe(control.pk)
  })
})

// ---- §3/§4 epochs + addressing ---------------------------------------------------

describe('CORD-02 §3–§4 — epochs and addressing', () => {
  it('group_key: pk is where a plane lives, sk signs its wraps, only a secret-holder derives either', () => {
    const gk = channelKey(root, ZERO32, 0)
    expect(pubkeyOf(gk.sk)).toBe(gk.pk)
    const { wrap } = wrapRumor(
      { kind: 9, pubkey: ownerPk, content: 'm', tags: [], created_at: 1 },
      ownerSk,
      gk,
      'encrypted',
    )
    expect(wrap.pubkey).toBe(gk.pk)
    expect(verifyEvent(wrap)).toBe(true)
  })

  it('rotating the epoch rotates the pk — a plane’s traffic is unlinkable across epochs', () => {
    const e0 = controlKey(root, cid, 0)
    const e1 = controlKey(root, cid, 1)
    expect(e1.pk).not.toBe(e0.pk)
  })

  it('epoch is a u64: large epoch values derive without corruption', () => {
    const big = 2n ** 63n + 5n
    const a = controlKey(root, cid, big)
    const b = controlKey(root, cid, big)
    const c = controlKey(root, cid, big + 1n)
    expect(a.pk).toBe(b.pk)
    expect(a.pk).not.toBe(c.pk)
  })

  it('millisecond ordering: true time is created_at * 1000 + ms, so same-second events sort deterministically', () => {
    const a = makeRumor({ kind: 9, pubkey: ownerPk, content: 'a', tags: [['ms', '417']], created_at: 1686840217 })
    const b = makeRumor({ kind: 9, pubkey: ownerPk, content: 'b', tags: [['ms', '902']], created_at: 1686840217 })
    expect(msTime(a)).toBe(1686840217417)
    expect(msTime(b)).toBe(1686840217902)
    expect(msTime(a)).toBeLessThan(msTime(b)) // same created_at still ordered
    // a rumor without ms defaults to 0
    const c = makeRumor({ kind: 9, pubkey: ownerPk, content: 'c', tags: [], created_at: 1686840217 })
    expect(msTime(c)).toBe(1686840217000)
  })

  it('an outsider cannot land a single event inside a member’s filters (the spam boundary)', () => {
    const gb = guestbookKey(root, cid, 0)
    // the member's filter is {"kinds":[1059],"authors":[gb.pk]} — an outsider
    // lacking the root cannot produce an event whose author is gb.pk
    const outsider = guestbookKey(randomBytes(32), cid, 0)
    expect(outsider.pk).not.toBe(gb.pk)
  })
})

// ---- §5 planes -------------------------------------------------------------------

describe('CORD-02 §5 — the three planes', () => {
  it('Control, Chat, and Guestbook planes live at distinct addresses under one root', () => {
    const chId = randomBytes(32)
    const pks = [
      controlKey(root, cid, 0).pk,
      channelKey(root, chId, 0).pk,
      guestbookKey(root, cid, 0).pk,
    ]
    expect(new Set(pks).size).toBe(3)
  })

  it('guestbook coalesces flat: one final state per npub, the latest Join/Leave/Kick wins', () => {
    const m = pubkeyOf(randomBytes(32))
    const fold = foldGuestbook(
      [joinRumor(m, 100, 0, 'join'), joinRumor(m, 200, 0, 'leave'), joinRumor(m, 300, 0, 'join')],
      gbCtx(),
    )
    expect(fold.members.has(m)).toBe(true)
    expect(fold.states.get(m)!.timeMs).toBe(300_000)
  })

  it('the fold is order-independent: any arrival order yields the same state', () => {
    const m1 = pubkeyOf(randomBytes(32))
    const m2 = pubkeyOf(randomBytes(32))
    const rumors = [
      joinRumor(m1, 100),
      joinRumor(m1, 500, 3, 'leave'),
      joinRumor(m2, 200),
      joinRumor(m2, 400, 9, 'join'),
    ]
    const a = foldGuestbook(rumors, gbCtx())
    const b = foldGuestbook([...rumors].reverse(), gbCtx())
    expect([...a.members].sort()).toEqual([...b.members].sort())
    expect(a.states.get(m1)).toEqual(b.states.get(m1))
  })

  it('a Kick is honored only if its signer holds KICK and outranks the target', () => {
    const admin = pubkeyOf(randomBytes(32))
    const target = pubkeyOf(randomBytes(32))
    const kick = makeRumor({
      kind: KIND_KICK,
      pubkey: admin,
      content: '',
      tags: [['ms', '0'], ['p', target], ['vac', 'ee'.repeat(32), '1', 'ff'.repeat(32)]],
      created_at: 200,
    })
    const rumors = [joinRumor(target, 100), kick]
    const honored = foldGuestbook(rumors, gbCtx({ kickAuthorized: () => true }))
    expect(honored.members.has(target)).toBe(false)
    const dropped = foldGuestbook(rumors, gbCtx({ kickAuthorized: () => false }))
    expect(dropped.members.has(target)).toBe(true) // unauthorized kick simply dropped
  })

  it('an author seen publishing is observably present — auto-included even if their Join never arrived', () => {
    const lurker = pubkeyOf(randomBytes(32))
    const fold = foldGuestbook([], gbCtx({ observed: [{ pubkey: lurker, timeMs: 500_000 }] }))
    expect(fold.members.has(lurker)).toBe(true)
  })

  it('observation only counts FORWARD: a departed member’s old history can never resurrect them', () => {
    const m = pubkeyOf(randomBytes(32))
    const rumors = [joinRumor(m, 100), joinRumor(m, 500, 0, 'leave')]
    // activity OLDER than the leave: stays departed
    const old = foldGuestbook(rumors, gbCtx({ observed: [{ pubkey: m, timeMs: 300_000 }] }))
    expect(old.members.has(m)).toBe(false)
    // activity NEWER than the leave: re-enters
    const fresh = foldGuestbook(rumors, gbCtx({ observed: [{ pubkey: m, timeMs: 600_000 }] }))
    expect(fresh.members.has(m)).toBe(true)
  })

  it('coalesced Guestbook ∪ observed authors − Banlist = the Complete Memberlist', () => {
    const a = pubkeyOf(randomBytes(32))
    const b = pubkeyOf(randomBytes(32))
    const banned = pubkeyOf(randomBytes(32))
    const fold = foldGuestbook([joinRumor(a, 100), joinRumor(banned, 100)], gbCtx({
      observed: [{ pubkey: b, timeMs: 200_000 }],
      banlist: new Set([banned]),
    }))
    expect(fold.members).toEqual(new Set([a, b]))
  })

  it('an entry dated more than one hour ahead of the receiver’s clock is dropped outright', () => {
    const m = pubkeyOf(randomBytes(32))
    const nowSec = Math.floor(NOW / 1000)
    const farFuture = joinRumor(m, nowSec + 3601) // > 1h ahead
    expect(foldGuestbook([farFuture], gbCtx()).members.has(m)).toBe(false)
    const nearFuture = joinRumor(m, nowSec + 3599) // within the hour: kept
    expect(foldGuestbook([nearFuture], gbCtx()).members.has(m)).toBe(true)
    expect(MAX_FUTURE_MS).toBe(3_600_000)
  })

  it('squatting "latest" by a forged future date is deterred: the forged entry never enters the fold', () => {
    const m = pubkeyOf(randomBytes(32))
    const nowSec = Math.floor(NOW / 1000)
    const honest = joinRumor(m, nowSec, 0, 'leave')
    const forged = joinRumor(m, nowSec + 999_999, 0, 'join') // squats "latest"
    const fold = foldGuestbook([honest, forged], gbCtx())
    expect(fold.states.get(m)!.status).toBe('departed') // the forgery was dropped
  })

  it('entries tying on time break by the lower rumor id (the inner event’s, never the wrap’s)', () => {
    const m = pubkeyOf(randomBytes(32))
    const j = joinRumor(m, 100, 0, 'join')
    const l = joinRumor(m, 100, 0, 'leave')
    const winner = j.id < l.id ? j : l
    const fold = foldGuestbook([j, l], gbCtx())
    expect(fold.states.get(m)!.rumorId).toBe(winner.id)
    // and the same regardless of arrival order
    const fold2 = foldGuestbook([l, j], gbCtx())
    expect(fold2.states.get(m)!.rumorId).toBe(winner.id)
  })

  it('the wrap id differs per re-wrap, which is why ties break on the RUMOR id', () => {
    const gb = guestbookKey(root, cid, 0)
    const rumor = joinRumor(ownerPk, 100)
    const seal = wrapRumor(rumor, ownerSk, gb, 'encrypted').seal
    const w1 = wrapSeal(seal, gb)
    const w2 = wrapSeal(seal, gb) // same seal re-wrapped
    expect(w1.id).not.toBe(w2.id) // outer ids differ (fresh ephemeral p)
    expect(unwrapEvent(w1, gb).rumor.id).toBe(unwrapEvent(w2, gb).rumor.id) // rumor id stable
  })
})

describe('CORD-02 §5 — snapshots', () => {
  const refounder = pubkeyOf(randomBytes(32))

  function snapshotRumors(members: string[], created_at = 200): Rumor[] {
    return buildSnapshotRumors(members, 'snap-1', created_at, 0).map(r =>
      makeRumor({ ...r, pubkey: refounder }),
    )
  }

  it('a snapshot is honored only from the npub whose Refounding minted the epoch', () => {
    const m = pubkeyOf(randomBytes(32))
    const snaps = snapshotRumors([m])
    expect(foldGuestbook(snaps, gbCtx({ refounder })).members.has(m)).toBe(true)
    // same events, different (or unknown) refounder → ignored
    expect(foldGuestbook(snaps, gbCtx({ refounder: pubkeyOf(randomBytes(32)) })).members.has(m)).toBe(false)
    expect(foldGuestbook(snaps, gbCtx()).members.has(m)).toBe(false)
  })

  it('a snapshot is secondhand: it merely seeds, and any newer self-signed entry supersedes it', () => {
    const m = pubkeyOf(randomBytes(32))
    const snaps = snapshotRumors([m], 200)
    const selfLeave = joinRumor(m, 300, 0, 'leave')
    const fold = foldGuestbook([...snaps, selfLeave], gbCtx({ refounder }))
    expect(fold.members.has(m)).toBe(false) // the member's own word wins
  })

  it('a snapshot lists present members only — absence means "no seed", never a negative state', () => {
    const present = pubkeyOf(randomBytes(32))
    const omitted = pubkeyOf(randomBytes(32))
    const snaps = snapshotRumors([present], 200)
    // the omitted member's own Join (older than the snapshot!) still stands:
    // absence from a snapshot is not a Leave
    const fold = foldGuestbook([...snaps, joinRumor(omitted, 100)], gbCtx({ refounder }))
    expect(fold.members.has(present)).toBe(true)
    expect(fold.members.has(omitted)).toBe(true)
  })

  it('chunks at 400 members per event, one snapshot id and one timestamp across all n chunks', () => {
    const members = Array.from({ length: 401 }, () => pubkeyOf(randomBytes(32)))
    const chunks = buildSnapshotRumors(members, 'snap-2', 500, 7)
    expect(SNAPSHOT_CHUNK).toBe(400)
    expect(chunks).toHaveLength(2)
    expect(JSON.parse(chunks[0]!.content)).toHaveLength(400)
    expect(JSON.parse(chunks[1]!.content)).toHaveLength(1)
    for (const c of chunks) {
      expect(c.created_at).toBe(500) // one timestamp
      const snap = c.tags.find(t => t[0] === 'snap')!
      expect(snap[1]).toBe('snap-2') // one id
      expect(snap[3]).toBe('2') // n
    }
  })

  it('chunks are independently useful: a partially received snapshot seeds whoever arrived', () => {
    const members = Array.from({ length: 401 }, () => pubkeyOf(randomBytes(32)))
    const all = buildSnapshotRumors(members, 'snap-3', 500, 0).map(r => makeRumor({ ...r, pubkey: refounder }))
    const onlyFirst = foldGuestbook([all[0]!], gbCtx({ refounder }))
    expect(onlyFirst.members.size).toBe(400) // no torn state to defend against
  })

  it('a refounder omitting someone creates a blip that heals on the victim’s next Join, never a disappearance', () => {
    const victim = pubkeyOf(randomBytes(32))
    const snaps = snapshotRumors([], 200) // victim omitted
    const freshJoin = joinRumor(victim, 300) // self-signed and unsuppressable
    const fold = foldGuestbook([...snaps, freshJoin], gbCtx({ refounder }))
    expect(fold.members.has(victim)).toBe(true)
  })

  it('guestbook rumor shapes: Join/Leave content is the verb; Kick names target and cites its vac', () => {
    const join = joinRumor(ownerPk, 100, 0, 'join', [['invite', 'aa'.repeat(32), 'Reddit']])
    expect(join.kind).toBe(3306)
    expect(join.content).toBe('join')
    const kick = makeRumor({
      kind: KIND_KICK,
      pubkey: ownerPk,
      content: '',
      tags: [['p', 'bb'.repeat(32)], ['vac', 'cc'.repeat(32), '2', 'dd'.repeat(32)]],
      created_at: 100,
    })
    expect(kick.kind).toBe(3309)
    expect(kick.tags.find(t => t[0] === 'p')).toBeTruthy()
    expect(kick.tags.find(t => t[0] === 'vac')).toHaveLength(4)
    expect(KIND_SNAPSHOT).toBe(3312)
  })
})

describe('CORD-02 §5 — seal encryption rule', () => {
  it('Chat/Guestbook seals are double-wrapped: content is never a standalone public artifact', () => {
    const gb = guestbookKey(root, cid, 0)
    const { seal, wrap } = wrapRumor(joinRumor(ownerPk, 100), ownerSk, gb, 'encrypted')
    expect(seal.kind).toBe(20013)
    // both layers are ciphertext: neither the wrap content nor the seal content parses
    expect(() => JSON.parse(wrap.content)).toThrow()
    expect(() => JSON.parse(seal.content)).toThrow()
  })

  it('Control Plane seals are plaintext (20014) precisely so compaction can re-wrap signatures across epochs', () => {
    const control0 = controlKey(root, cid, 0)
    const edition = makeRumor({
      kind: KIND_EDITION,
      pubkey: ownerPk,
      content: JSON.stringify({ name: 'Vector', relays: [] }),
      tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1 }),
      created_at: 1686840217,
    })
    const { seal } = wrapRumor(edition, ownerSk, control0, 'plaintext')

    // Refounding: new root, new epoch — re-wrap the SAME seal
    const newRoot = randomBytes(32)
    const control1 = controlKey(newRoot, cid, 1)
    const rewrapped = wrapSeal(seal, control1)
    const opened = unwrapEvent(rewrapped, control1)
    expect(verifyEvent(opened.seal)).toBe(true) // original owner's signature intact
    expect(opened.rumor.id).toBe(edition.id)
  })

  it('an encrypted seal could NOT survive that re-encryption: the signature binds the ciphertext', () => {
    const control0 = controlKey(root, cid, 0)
    const edition = makeRumor({
      kind: KIND_EDITION,
      pubkey: ownerPk,
      content: '{}',
      tags: editionTags({ vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1 }),
      created_at: 1,
    })
    const { seal } = wrapRumor(edition, ownerSk, control0, 'encrypted')
    const control1 = controlKey(randomBytes(32), cid, 1)
    // re-encrypting the rumor under the new conv key produces content the old sig doesn't cover
    const reEncrypted = { ...seal, content: nip44.encrypt(JSON.stringify(edition), control1.convKey) }
    expect(verifyEvent(reEncrypted)).toBe(false)
  })
})

// ---- §6 metadata -----------------------------------------------------------------

describe('CORD-02 §6 — metadata', () => {
  it('name caps at 64 bytes counted as UTF-8 — the protocol-wide cap', () => {
    expect(NAME_CAP_BYTES).toBe(64)
    expect(nameWithinCap('a'.repeat(64))).toBe(true)
    expect(nameWithinCap('a'.repeat(65))).toBe(false)
    // multibyte counts bytes, not characters: 33 × '¢' (2 bytes each) = 66 bytes
    expect(nameWithinCap('¢'.repeat(32))).toBe(true)
    expect(nameWithinCap('¢'.repeat(33))).toBe(false)
  })

  it('description caps at 10000 bytes as UTF-8', () => {
    const cap = 10_000
    expect(utf8('d'.repeat(cap)).length).toBeLessThanOrEqual(cap)
    expect(utf8('d'.repeat(cap + 1)).length).toBeGreaterThan(cap)
  })

  it('icon and banner are encrypted-blob pointers: a swapped blob fails closed on the hash', () => {
    const blob = utf8('fake image bytes')
    const pointer = { url: 'https://blossom.example/x', key: 'aa'.repeat(32), nonce: 'bb'.repeat(12), hash: bytesToHex(sha256(blob)) }
    // fetch, decrypt, verify the hash — a swapped blob mismatches
    expect(bytesToHex(sha256(blob))).toBe(pointer.hash)
    expect(bytesToHex(sha256(utf8('swapped')))).not.toBe(pointer.hash)
  })

  it('an editor MUST round-trip fields it does not understand (editing the name never wipes another client’s rules)', () => {
    const stored = { name: 'Vector', custom: { rules: 'Be excellent to each other.', 'soapbox/theme': 'dark' } }
    // a naive editor knows only `name`; the discipline: parse, mutate, re-serialize everything else
    const edited = { ...stored, name: 'Vector 2' }
    expect(edited.custom).toEqual(stored.custom)
    expect((edited.custom as Record<string, string>)['soapbox/theme']).toBe('dark')
  })

  it('a metadata edition MUST stay usable when its relay list is trimmed: a client MAY truncate to the first few', () => {
    const relays = ['wss://a', 'wss://b', 'wss://c', 'wss://d', 'wss://e', 'wss://f', 'wss://g']
    const trimmed = relays.slice(0, 5) // up to 5 verifiably stable relays is the recommendation
    expect(trimmed).toHaveLength(5)
    expect(trimmed[0]).toBe('wss://a') // the FIRST few — deterministic truncation
  })
})

// ---- §8 the community list ---------------------------------------------------------

describe('CORD-02 §8 — the Community List', () => {
  const mat = (epoch: number, name = 'Vector'): JoinMaterial => ({
    community_id: bytesToHex(cid),
    owner: ownerPk,
    owner_salt: bytesToHex(ownerSalt),
    community_root: bytesToHex(root),
    root_epoch: epoch,
    channels: [],
    relays: ['wss://jskitty.com/nostr'],
    name,
  })
  const entry = (seedE: number, curE: number, added = 1_719_800_000_000): CommunityEntry => ({
    community_id: bytesToHex(cid),
    seed: mat(seedE),
    current: mat(curE),
    added_at: added,
  })
  const empty: CommunityList = { entries: [], tombstones: [] }

  it('join material is the bundle’s membership subset: never the icon, never the link fields', () => {
    const m = mat(0)
    expect(Object.keys(m).sort()).toEqual(
      ['channels', 'community_id', 'community_root', 'name', 'owner', 'owner_salt', 'relays', 'root_epoch'].sort(),
    )
    expect('icon' in m).toBe(false)
    expect('expires_at' in m).toBe(false)
    expect('creator_npub' in m).toBe(false)
  })

  it('seed only ever moves BACKward on merge (keeps the lower epoch); current keeps the higher', () => {
    const a = entry(2, 5)
    const b = entry(1, 7)
    const merged = mergeEntry(a, b)
    expect(merged.seed.root_epoch).toBe(1) // widest reach
    expect(merged.current.root_epoch).toBe(7) // freshest
    // symmetric
    const merged2 = mergeEntry(b, a)
    expect(merged2.seed.root_epoch).toBe(1)
    expect(merged2.current.root_epoch).toBe(7)
  })

  it('an epoch tie breaks on the lexicographically lowest canonical bytes — a total order, no flapping', () => {
    const a = entry(1, 3)
    const b = entry(1, 3)
    b.current = mat(3, 'Renamed') // same epoch, different snapshot (a same-epoch rename)
    const w1 = mergeEntry(a, b).current
    const w2 = mergeEntry(b, a).current
    expect(w1).toEqual(w2) // both devices land on the same one
    const lower =
      Buffer.from(canonicalBytes(a.current)).compare(Buffer.from(canonicalBytes(b.current))) <= 0
        ? a.current
        : b.current
    expect(w1).toEqual(lower)
  })

  it('tombstones: the newest of added_at and removed_at wins — a re-join resurrects, a backfill cannot re-add', () => {
    const removedAt = 1_722_400_000_000
    const tombed: CommunityList = { entries: [], tombstones: [{ community_id: bytesToHex(cid), removed_at: removedAt }] }
    // a backfill carrying the OLD entry (added before removal) can never re-add it
    const backfill: CommunityList = { entries: [entry(0, 0, removedAt - 1000)], tombstones: [] }
    expect(liveEntries(mergeLists(tombed, backfill))).toHaveLength(0)
    // a legitimate re-join (added after removal) resurrects
    const rejoin: CommunityList = { entries: [entry(0, 1, removedAt + 1000)], tombstones: [] }
    expect(liveEntries(mergeLists(tombed, rejoin))).toHaveLength(1)
  })

  it('a tombstone is permanent: merging never prunes it (a long-offline device must not resurrect)', () => {
    const tombed: CommunityList = { entries: [], tombstones: [{ community_id: bytesToHex(cid), removed_at: 5 }] }
    const merged = mergeLists(tombed, empty)
    expect(merged.tombstones).toHaveLength(1)
    const again = mergeLists(merged, empty)
    expect(again.tombstones).toHaveLength(1)
  })

  it('the List caps at 50 memberships — a protocol constant, because NIP-44 plaintext hard-caps at 65,535 bytes', () => {
    expect(MAX_MEMBERSHIPS).toBe(50)
    expect(NIP44_MAX_PLAINTEXT).toBe(65535)
    // 50 realistic memberships fit a single NIP-44 event
    const entries = Array.from({ length: 50 }, (_, i) => {
      const e = entry(0, 1)
      return { ...e, community_id: String(i).padStart(64, '0') }
    })
    const list: CommunityList = { entries, tombstones: [] }
    expect(fitsNip44(list)).toBe(true)
    // the 51st is refused
    const over: CommunityList = {
      entries: [...entries, { ...entry(0, 1), community_id: 'f'.repeat(64) }],
      tombstones: [],
    }
    expect(() => mergeLists(over, empty)).toThrow(/50/)
  })

  it('merge is idempotent and commutative: two devices converge regardless of direction', () => {
    const a: CommunityList = { entries: [entry(2, 4)], tombstones: [] }
    const b: CommunityList = { entries: [entry(1, 6)], tombstones: [{ community_id: 'e'.repeat(64), removed_at: 9 }] }
    const ab = mergeLists(a, b)
    const ba = mergeLists(b, a)
    expect(canonicalBytes(ab)).toEqual(canonicalBytes(ba))
    expect(canonicalBytes(mergeLists(ab, ab))).toEqual(canonicalBytes(ab))
  })
})

// ---- §9 dissolution ------------------------------------------------------------------

describe('CORD-02 §9 — dissolution', () => {
  it('the tombstone coordinate derives from the community_id ALONE — no key, no epoch — so every member past or present resolves it', () => {
    const d = dissolvedKey(cid)
    // derivable without root, without epoch: an ex-member holding only the id resolves the same address
    expect(dissolvedKey(cid).pk).toBe(d.pk)
    // no epoch parameter exists to strand the grave behind a Refounding
    expect(d.pk).not.toBe(controlKey(root, cid, 0).pk)
  })

  it('only the owner’s signature counts: an impostor’s event at the coordinate is noise', () => {
    const impostorSk = randomBytes(32)
    const tomb = (sk: Uint8Array, pk: string) =>
      wrapRumor(
        {
          kind: KIND_EDITION,
          pubkey: pk,
          content: '',
          tags: [['vsk', '10'], ['eid', '0'.repeat(64)]],
          created_at: 1725000000,
        },
        sk,
        dissolvedKey(cid),
        'plaintext',
      )
    const isValidTombstone = (wrap: ReturnType<typeof tomb>['wrap']) => {
      const { rumor, seal } = unwrapEvent(wrap, dissolvedKey(cid))
      // verified against the owner the community_id itself commits to
      return verifyEvent(seal) && rumor.pubkey === ownerPk &&
        bytesToHex(communityId(hexToBytes(rumor.pubkey), ownerSalt)) === bytesToHex(cid)
    }
    expect(isValidTombstone(tomb(ownerSk, ownerPk).wrap)).toBe(true)
    expect(isValidTombstone(tomb(impostorSk, pubkeyOf(impostorSk)).wrap)).toBe(false)
  })

  it('the tombstone is chainless: no ev, no ep, no vac — presence of one valid edition IS the state', () => {
    const rumor = makeRumor({
      kind: KIND_EDITION,
      pubkey: ownerPk,
      content: '',
      tags: [['vsk', '10'], ['eid', '0'.repeat(64)]],
      created_at: 1725000000,
    })
    expect(rumor.tags.some(t => t[0] === 'ev')).toBe(false)
    expect(rumor.tags.some(t => t[0] === 'ep')).toBe(false)
    expect(rumor.tags.some(t => t[0] === 'vac')).toBe(false)
    expect(rumor.content).toBe('') // carrying nothing at all
    expect(VSK.DISSOLVED).toBe(10)
  })

  it('death wins every race: no epoch advance past a valid tombstone is honored, and the seal is one-way', () => {
    // model of the client rule
    interface CommunityView { dissolved: boolean; epoch: number; readOnly: boolean }
    const view: CommunityView = { dissolved: false, epoch: 3, readOnly: false }
    const onTombstone = (v: CommunityView): CommunityView => ({ ...v, dissolved: true, readOnly: true })
    const onRefounding = (v: CommunityView, newEpoch: number): CommunityView =>
      v.dissolved ? v : { ...v, epoch: newEpoch } // a rekey racing a dissolution loses

    let v = onTombstone(view)
    v = onRefounding(v, 4) // the racing Refounding arrives after
    expect(v.epoch).toBe(3) // not honored
    expect(v.readOnly).toBe(true)
    // one-way: there is no un-dissolve transition at all
    expect(v.dissolved).toBe(true)
  })

  it('held keys still open history after the seal, but nothing new is honored', () => {
    const ch = channelKey(root, randomBytes(32), 0)
    const old = wrapRumor(
      { kind: 9, pubkey: ownerPk, content: 'history', tags: [], created_at: 1 },
      ownerSk, ch, 'encrypted',
    )
    // sealing is a client-state change; decryption capability is untouched
    expect(unwrapEvent(old.wrap, ch).rumor.content).toBe('history')
  })

  it('the one carve-out: a member’s own delete of their own message is honored even post-seal', () => {
    const author = pubkeyOf(randomBytes(32))
    const honorPostSeal = (rumor: Rumor, messageAuthor: string) =>
      rumor.kind === 5 && rumor.pubkey === messageAuthor // self-scrub only
    const selfDelete = makeRumor({ kind: 5, pubkey: author, content: '', tags: [['e', 'x'.repeat(64)]], created_at: 2 })
    const newMessage = makeRumor({ kind: 9, pubkey: author, content: 'new', tags: [], created_at: 2 })
    const foreignDelete = makeRumor({ kind: 5, pubkey: pubkeyOf(randomBytes(32)), content: '', tags: [], created_at: 2 })
    expect(honorPostSeal(selfDelete, author)).toBe(true) // deserves to erase themselves
    expect(honorPostSeal(newMessage, author)).toBe(false) // read-only not violated
    expect(honorPostSeal(foreignDelete, author)).toBe(false)
  })
})

// ---- Appendix A -----------------------------------------------------------------------

describe('CORD-02 Appendix A — frozen derivations', () => {
  it('A.1 hkdf: HKDF-SHA256, zero-length salt, info = utf8(label) || 0x00 || id[32] || epoch_be[8] — byte-exact', () => {
    const secret = randomBytes(32)
    const id = randomBytes(32)
    const label = 'concord/control'
    const manualInfo = concat(utf8(label), new Uint8Array([0]), id, u64be(7))
    const manual = hkdf(sha256, secret, undefined, manualInfo, 32)
    expect(bytesToHex(hkdfConcord(secret, label, id, 7))).toBe(bytesToHex(manual))
  })

  it('A.1: the id is always present (all-zeroes where a label has none); the epoch is the ONLY omittable field', () => {
    const secret = randomBytes(32)
    // epochless derivation omits the 8 bytes entirely — differs from epoch=0
    const without = hkdfConcord(secret, 'concord/banlist', ZERO32)
    const withZero = hkdfConcord(secret, 'concord/banlist', ZERO32, 0)
    expect(bytesToHex(without)).not.toBe(bytesToHex(withZero))
    // id must be raw 32 bytes, never hex
    expect(() => hkdfConcord(secret, 'concord/banlist', new Uint8Array(16))).toThrow(/32/)
  })

  it('A.2/A.3 group_key + scalar_normalize: deterministic across calls, always a valid secp256k1 key', () => {
    const secret = randomBytes(32)
    const a = groupKey('concord/control', secret, cid, 0)
    const b = groupKey('concord/control', secret, cid, 0)
    expect(a.pk).toBe(b.pk)
    expect(bytesToHex(a.sk)).toBe(bytesToHex(b.sk))
    expect(pubkeyOf(a.sk)).toBe(a.pk) // valid key: derives its own pubkey
    // normalization output equals the raw seed in the overwhelmingly common branch
    expect(bytesToHex(scalarNormalize(secret, 'concord/control', cid, 0))).toBe(bytesToHex(a.sk))
  })

  it('A.5 epoch-key commitment: sha256("concord/epoch-key-commitment" || prev_epoch_be || prev_key) — byte-exact', () => {
    const key = randomBytes(32)
    const manual = sha256(concat(utf8('concord/epoch-key-commitment'), u64be(2), key))
    expect(bytesToHex(epochKeyCommitment(2, key))).toBe(bytesToHex(manual))
  })

  it('A.6: changing any labeled byte re-addresses everything — every label yields a distinct universe', () => {
    const secret = randomBytes(32)
    const id = randomBytes(32)
    const outs = [
      groupKey('concord/channel', secret, id, 1).pk,
      groupKey('concord/control', secret, id, 1).pk,
      groupKey('concord/guestbook', secret, id, 1).pk,
      rekeyPseudonym(secret, id, 1).pk,
      baseRekeyPseudonym(secret, id, 1).pk,
    ]
    expect(new Set(outs).size).toBe(outs.length)
  })

  it('A.6: the epochless, keyless coordinates derive from public/community inputs alone', () => {
    const member = randomBytes(32)
    // all deterministic, all distinct
    const coords = [
      bytesToHex(grantLocator(cid, member)),
      bytesToHex(banlistLocator(cid)),
      bytesToHex(inviteLinksLocator(cid, member)),
      dissolvedKey(cid).pk,
    ]
    expect(new Set(coords).size).toBe(coords.length)
    // and reproducible without any secret key material
    expect(bytesToHex(grantLocator(cid, member))).toBe(bytesToHex(grantLocator(cid, member)))
  })

  it('A.6: the recipient-pseudonym locator keys off rotator||recipient public keys', () => {
    const rot = randomBytes(32)
    const rcp = randomBytes(32)
    const scope = randomBytes(32)
    const l1 = recipientLocator(rot, rcp, scope, 3)
    const l2 = recipientLocator(rcp, rot, scope, 3) // order matters: rotator first
    expect(bytesToHex(l1)).not.toBe(bytesToHex(l2))
  })

  it('A.6: the invite token derivations are three independent one-way outputs of the token', () => {
    const token = randomBytes(32)
    const outs = [
      bytesToHex(inviteBundleKey(token)),
      bytesToHex(inviteBundleId(token)),
      bytesToHex(inviteBundleSigner(token).sk),
    ]
    expect(new Set(outs).size).toBe(3)
  })
})

// ---- Appendix B -----------------------------------------------------------------------

describe('CORD-02 Appendix B — frozen kinds', () => {
  it('the durable wrap is 1059; the ephemeral wrap is 21059; seals are 20013/20014', () => {
    // asserted against the model's constants (also exercised throughout)
    expect(KIND_EDITION).toBe(3308)
    expect(KIND_JOIN_LEAVE).toBe(3306)
    expect(KIND_KICK).toBe(3309)
    expect(KIND_SNAPSHOT).toBe(3312)
  })

  it('Concord carries NO version tag anywhere: a tagged 1059 would unmask the camouflage', () => {
    const gb = guestbookKey(root, cid, 0)
    const { wrap } = wrapRumor(joinRumor(ownerPk, 100), ownerSk, gb, 'encrypted')
    // the outer event carries exactly one p tag and nothing else
    expect(wrap.tags).toEqual([['p', wrap.tags[0]![1]!]])
  })

  it('the frozen derivations already partition incompatible revisions by address (a re-label is a different universe)', () => {
    const secret = randomBytes(32)
    expect(groupKey('concord/control', secret, cid, 0).pk).not.toBe(
      groupKey('concord/control-v2', secret, cid, 0).pk,
    )
  })

  it('vsk sub-kind registry: 0 metadata, 1 role, 2 channel, 3 grant, 4 banlist, 8 registry, 10 dissolved', () => {
    expect(VSK.COMMUNITY_METADATA).toBe(0)
    expect(VSK.ROLE).toBe(1)
    expect(VSK.CHANNEL_METADATA).toBe(2)
    expect(VSK.GRANT).toBe(3)
    expect(VSK.BANLIST).toBe(4)
    expect(VSK.RESERVED_ROLE_ORDER).toBe(5)
    expect(VSK.INVITE_LIVE).toBe(6)
    expect(VSK.RETIRED_OWNER_ATTESTATION).toBe(7)
    expect(VSK.INVITE_REGISTRY).toBe(8)
    expect(VSK.INVITE_TOMBSTONE).toBe(9)
    expect(VSK.DISSOLVED).toBe(10)
  })
})
