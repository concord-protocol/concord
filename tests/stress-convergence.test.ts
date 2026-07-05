/**
 * Stress: convergence. The specs' central promise is that every client,
 * receiving the same events in ANY order (or merging state along any tree),
 * lands on the identical state. These tests hammer that promise with
 * seeded-random orderings, partitions, and concurrent-actor schedules.
 *
 * Every claim here quotes the spec's own words:
 *  - CORD-04 §1: "Every client walks the same chain and lands on the same head."
 *  - CORD-02 §5: "deterministic when synced, self-healing when not"
 *  - CORD-02 §8: "a total order, so a same-epoch rename can't leave two
 *    devices flapping competing republishes"
 *  - CORD-04 §4: "Re-heal guarantees convergence to the union"
 */
import { describe, expect, it } from 'vitest'
import { bytesToHex, hexToBytes, randomBytes } from '../src/bytes.js'
import { communityId } from '../src/derive.js'
import { editionTags, editionHash, foldControl, grantEid, banlistEid, KIND_EDITION, VSK, type ControlState, type FoldContext } from '../src/editions.js'
import { makeRumor, pubkeyOf, type Rumor } from '../src/events.js'
import { foldGuestbook, KIND_JOIN_LEAVE, KIND_KICK, KIND_SNAPSHOT, type GuestbookContext } from '../src/guestbook.js'
import { canonicalBytes, mergeLists, type CommunityList, type JoinMaterial } from '../src/communityList.js'
import { mergeInviteLists, type InviteList } from '../src/invites.js'
import { PERM, rehealBanlist, writePermissions, type Role } from '../src/roster.js'
import { prng, shuffled, pick, randomHex } from './helpers/rand.js'

const SHUFFLES = 30

// ---- control plane fold ----------------------------------------------------------

describe('stress — control fold convergence (CORD-04 §1)', () => {
  const ownerSk = randomBytes(32)
  const ownerPk = pubkeyOf(ownerSk)
  const cid = communityId(hexToBytes(ownerPk), randomBytes(32))
  const ctx: FoldContext = { ownerPk, communityId: cid }

  const alice = pubkeyOf(randomBytes(32))
  const bob = pubkeyOf(randomBytes(32))
  const carol = pubkeyOf(randomBytes(32))
  const mallory = pubkeyOf(randomBytes(32))

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
  function role(id: string, position: number, perms: bigint): Role {
    return { role_id: id, name: 'r', position, permissions: writePermissions(perms), scope: { kind: 'server' }, color: 0 }
  }
  const hashOf = (r: Rumor) => {
    const ev = r.tags.find(t => t[0] === 'ev')![1]!
    const eid = r.tags.find(t => t[0] === 'eid')![1]!
    const ep = r.tags.find(t => t[0] === 'ep')?.[1] ?? null
    return bytesToHex(editionHash(hexToBytes(eid), Number(ev), ep ? hexToBytes(ep) : null, new TextEncoder().encode(r.content)))
  }

  /** A dense, adversarial history: chains, demotions, races, forgeries, garbage. */
  function history(): Rumor[] {
    const ADMIN = 'aa'.repeat(32)
    const MOD = 'bb'.repeat(32)
    const adminRole = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: ADMIN, version: 1, content: role(ADMIN, 1, PERM.MANAGE_ROLES | PERM.BAN | PERM.MANAGE_METADATA | PERM.MANAGE_CHANNELS) })
    const modRole = edition({ signer: ownerPk, vsk: VSK.ROLE, eid: MOD, version: 1, content: role(MOD, 2, PERM.KICK | PERM.MANAGE_MESSAGES) })
    const aliceG1 = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alice), version: 1, content: { member: alice, role_ids: [ADMIN] } })
    const aliceVac = { eid: grantEid(cid, alice), version: 1, hash: hashOf(aliceG1) }
    const bobG1 = edition({ signer: alice, vsk: VSK.GRANT, eid: grantEid(cid, bob), version: 1, vac: aliceVac, content: { member: bob, role_ids: [MOD] } })
    const bobG2 = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, bob), version: 2, prev: hashOf(bobG1), content: { member: bob, role_ids: [ADMIN] } })
    const bobVac2 = { eid: grantEid(cid, bob), version: 2, hash: hashOf(bobG2) }
    // metadata chain v1..v3 with a same-version race at v2 (owner vs alice)
    const m1 = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'v1', relays: [] } })
    const m2a = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 2, prev: hashOf(m1), content: { name: 'v2-owner', relays: [] } })
    const m2b = edition({ signer: alice, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 2, prev: hashOf(m1), vac: aliceVac, content: { name: 'v2-alice', relays: [] } })
    const m3 = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 3, prev: hashOf(m2a), content: { name: 'v3', relays: [] } })
    // banlist races: alice and bob (both BAN) ban different people at v1
    const b1a = edition({ signer: alice, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: aliceVac, content: [carol] })
    const b1b = edition({ signer: bob, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: bobVac2, content: [mallory] })
    // alice demoted at v2 — her later channel edit must never fold
    const aliceG2 = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alice), version: 2, prev: hashOf(aliceG1), content: { member: alice, role_ids: [] } })
    const staleAlice = edition({ signer: alice, vsk: VSK.CHANNEL_METADATA, eid: 'cc'.repeat(32), version: 1, vac: aliceVac, content: { name: 'stale', private: false } })
    // forgeries and garbage that must never fold anywhere
    const forgedRoster = edition({ signer: mallory, vsk: VSK.ROLE, eid: 'dd'.repeat(32), version: 1, vac: { eid: grantEid(cid, mallory), version: 1, hash: 'ee'.repeat(32) }, content: role('dd'.repeat(32), 1, PERM.BAN) })
    const brokenChain = edition({ signer: ownerPk, vsk: VSK.CHANNEL_METADATA, eid: 'ff'.repeat(32), version: 2, prev: '12'.repeat(32), content: { name: 'dangling', private: false } })
    const garbage1 = makeRumor({ kind: KIND_EDITION, pubkey: ownerPk, content: 'not json {{', tags: [['vsk', '1'], ['eid', '99'.repeat(32)], ['ev', '1']], created_at: 1 })
    const garbage2 = makeRumor({ kind: KIND_EDITION, pubkey: ownerPk, content: '{}', tags: [['vsk', '0'], ['eid', 'zz-not-hex'], ['ev', '1']], created_at: 1 })
    const garbage3 = makeRumor({ kind: KIND_EDITION, pubkey: ownerPk, content: '{}', tags: [['vsk', '0'], ['eid', '77'.repeat(32)], ['ev', '-4']], created_at: 1 })
    return [adminRole, modRole, aliceG1, bobG1, bobG2, m1, m2a, m2b, m3, b1a, b1b, aliceG2, staleAlice, forgedRoster, brokenChain, garbage1, garbage2, garbage3]
  }

  function fingerprint(s: ControlState): string {
    const ents = [...s.entities.entries()]
      .map(([eid, e]) => `${eid}:${e.version}:${e.hash}:${e.signer}`)
      .sort()
    return JSON.stringify({ ents, susp: [...s.suspended].sort(), ban: [...s.banlist].sort() })
  }

  it('every arrival order folds to the identical state — races, demotions, forgeries and garbage included', () => {
    const events = history()
    const baseline = fingerprint(foldControl(events.map(rumor => ({ rumor })), ctx))
    const rand = prng(0xc0ffee)
    for (let i = 0; i < SHUFFLES; i++) {
      const order = shuffled(events, rand)
      expect(fingerprint(foldControl(order.map(rumor => ({ rumor })), ctx))).toBe(baseline)
    }
  })

  it('the folded state itself is sane under every shuffle: demoted alice never folds, mallory never appears, garbage vanishes', () => {
    const events = history()
    const rand = prng(0xbeef)
    for (let i = 0; i < 10; i++) {
      const s = foldControl(shuffled(events, rand).map(rumor => ({ rumor })), ctx)
      expect(s.entities.has('cc'.repeat(32))).toBe(false) // stale alice edit
      expect(s.entities.has('dd'.repeat(32))).toBe(false) // mallory's forged role
      expect(s.entities.has('99'.repeat(32))).toBe(false) // garbage
      expect(JSON.parse(s.entities.get(bytesToHex(cid))!.content).name).toBe('v3')
    }
  })

  it('any SUBSET of history folds without error, and re-adding the missing events converges back (self-healing)', () => {
    const events = history()
    const rand = prng(0x5eed)
    const full = fingerprint(foldControl(events.map(rumor => ({ rumor })), ctx))
    for (let i = 0; i < 20; i++) {
      const subset = events.filter(() => rand() > 0.4)
      expect(() => foldControl(subset.map(rumor => ({ rumor })), ctx)).not.toThrow()
      // healing: subset ∪ rest = full, regardless of which half arrived first
      const rest = events.filter(e => !subset.includes(e))
      const healed = foldControl([...subset, ...rest].map(rumor => ({ rumor })), ctx)
      expect(fingerprint(healed)).toBe(full)
    }
  })
})

// ---- guestbook fold ------------------------------------------------------------------

describe('stress — guestbook fold convergence (CORD-02 §5)', () => {
  const NOW = 1_722_000_000_000
  const refounder = pubkeyOf(randomBytes(32))
  const members = Array.from({ length: 20 }, () => pubkeyOf(randomBytes(32)))
  const admin = pubkeyOf(randomBytes(32))

  function randomHistory(seed: number): Rumor[] {
    const rand = prng(seed)
    const out: Rumor[] = []
    const base = Math.floor(NOW / 1000) - 10_000
    for (let i = 0; i < 250; i++) {
      const m = pick(members, rand)
      const t = base + Math.floor(rand() * 12_000) // some beyond the +1h window
      const ms = Math.floor(rand() * 1000)
      const kind = rand()
      if (kind < 0.45) {
        out.push(makeRumor({ kind: KIND_JOIN_LEAVE, pubkey: m, content: 'join', tags: [['ms', String(ms)]], created_at: t }))
      } else if (kind < 0.8) {
        out.push(makeRumor({ kind: KIND_JOIN_LEAVE, pubkey: m, content: 'leave', tags: [['ms', String(ms)]], created_at: t }))
      } else if (kind < 0.9) {
        out.push(makeRumor({ kind: KIND_KICK, pubkey: admin, content: '', tags: [['ms', String(ms)], ['p', m], ['vac', randomHex(rand), '1', randomHex(rand)]], created_at: t }))
      } else if (kind < 0.97) {
        const listed = members.filter(() => rand() > 0.5)
        out.push(makeRumor({ kind: KIND_SNAPSHOT, pubkey: rand() > 0.3 ? refounder : m /* some impostor snapshots */, content: JSON.stringify(listed), tags: [['ms', String(ms)], ['snap', 's1', '1', '1']], created_at: t }))
      } else {
        // malformed ms values — must be dropped, not interpreted
        out.push(makeRumor({ kind: KIND_JOIN_LEAVE, pubkey: m, content: 'join', tags: [['ms', pick(['5000', '-1', '1e3', 'NaN', '999999'], rand)]], created_at: t }))
      }
    }
    return out
  }

  const ctx = (): GuestbookContext => ({
    nowMs: NOW,
    refounder,
    kickAuthorized: () => true,
    banlist: new Set([members[0]!]),
    observed: [{ pubkey: members[1]!, timeMs: NOW - 1000 }],
  })

  function fingerprint(rumors: Rumor[]): string {
    const fold = foldGuestbook(rumors, ctx())
    const states = [...fold.states.entries()].map(([k, v]) => `${k}:${v.status}:${v.timeMs}:${v.rumorId}`).sort()
    return JSON.stringify({ states, members: [...fold.members].sort() })
  }

  it('250 random joins/leaves/kicks/snapshots (plus impostor snapshots and malformed ms) fold identically under every shuffle', () => {
    const events = randomHistory(0xabcdef)
    const baseline = fingerprint(events)
    const rand = prng(0x777)
    for (let i = 0; i < SHUFFLES; i++) {
      expect(fingerprint(shuffled(events, rand))).toBe(baseline)
    }
  })

  it('folding twice is folding once: the coalesce is idempotent over duplicated history', () => {
    const events = randomHistory(0x1234)
    expect(fingerprint([...events, ...events])).toBe(fingerprint(events))
  })

  it('the banlist subtraction and forged-future drops hold under every ordering', () => {
    const events = randomHistory(0x4242)
    const rand = prng(0x4243)
    for (let i = 0; i < 5; i++) {
      const fold = foldGuestbook(shuffled(events, rand), ctx())
      expect(fold.members.has(members[0]!)).toBe(false) // banned never surfaces
      for (const [, st] of fold.states) {
        expect(st.timeMs).toBeLessThanOrEqual(NOW + 3_600_000) // nothing beyond the window
      }
    }
  })
})

// ---- community list merge ---------------------------------------------------------------

describe('stress — Community List merge algebra (CORD-02 §8)', () => {
  const mat = (epoch: number, name: string): JoinMaterial => ({
    community_id: '', owner: 'o'.repeat(64), owner_salt: 's'.repeat(64),
    community_root: 'r'.repeat(64), root_epoch: epoch, channels: [], relays: [], name,
  })

  function randomList(seed: number): CommunityList {
    const rand = prng(seed)
    const ids = Array.from({ length: 8 }, (_, i) => String(i).padStart(64, '0'))
    const entries = ids.filter(() => rand() > 0.4).map(id => ({
      community_id: id,
      seed: { ...mat(Math.floor(rand() * 5), 'seed'), community_id: id },
      current: { ...mat(5 + Math.floor(rand() * 5), pick(['A', 'B', 'C'], rand)), community_id: id },
      added_at: 1_700_000_000_000 + Math.floor(rand() * 1_000_000),
    }))
    const tombstones = ids.filter(() => rand() > 0.7).map(id => ({
      community_id: id,
      removed_at: 1_700_000_000_000 + Math.floor(rand() * 1_000_000),
    }))
    return { entries, tombstones }
  }

  const fp = (l: CommunityList) =>
    JSON.stringify({
      e: l.entries.map(e => new TextDecoder().decode(canonicalBytes(e))).sort(),
      t: l.tombstones.map(t => JSON.stringify(t)).sort(),
    })

  it('merge is commutative, associative, and idempotent across random device states — no merge tree flaps', () => {
    for (let seed = 1; seed <= 15; seed++) {
      const a = randomList(seed * 3 + 1)
      const b = randomList(seed * 3 + 2)
      const c = randomList(seed * 3 + 3)
      expect(fp(mergeLists(a, b))).toBe(fp(mergeLists(b, a))) // commutative
      expect(fp(mergeLists(mergeLists(a, b), c))).toBe(fp(mergeLists(a, mergeLists(b, c)))) // associative
      const ab = mergeLists(a, b)
      expect(fp(mergeLists(ab, ab))).toBe(fp(ab)) // idempotent
      expect(fp(mergeLists(ab, a))).toBe(fp(ab)) // re-merging an ancestor changes nothing
    }
  })

  it('N devices syncing pairwise in any random order all converge to one list', () => {
    const rand = prng(0xd15c)
    const devices = Array.from({ length: 5 }, (_, i) => randomList(100 + i))
    // full pairwise gossip, random order, until stable
    for (let round = 0; round < 4; round++) {
      const order = shuffled(devices.map((_, i) => i), rand)
      for (const i of order) {
        for (const j of shuffled(devices.map((_, k) => k).filter(k => k !== i), rand)) {
          const merged = mergeLists(devices[i]!, devices[j]!)
          devices[i] = merged
          devices[j] = merged
        }
      }
    }
    const first = fp(devices[0]!)
    for (const d of devices) expect(fp(d)).toBe(first)
  })
})

// ---- invite list merge --------------------------------------------------------------------

describe('stress — Invite List merge algebra (CORD-05 §4)', () => {
  function randomInviteList(seed: number): InviteList {
    const rand = prng(seed)
    const tokens = Array.from({ length: 10 }, (_, i) => String(i).padStart(64, 'a'))
    return {
      entries: tokens.filter(() => rand() > 0.4).map(t => ({
        token: t, community_id: 'c'.repeat(64), url: `https://x/#${t.slice(0, 6)}`, created_at: 1,
      })),
      tombstones: tokens.filter(() => rand() > 0.7).map(t => ({ token: t, community_id: 'c'.repeat(64) })),
    }
  }
  const fp = (l: InviteList) =>
    JSON.stringify({ e: l.entries.map(e => e.token).sort(), t: l.tombstones.map(t => t.token).sort() })

  it('merge is commutative, associative, idempotent; tombstones dominate under every composition', () => {
    for (let seed = 1; seed <= 15; seed++) {
      const a = randomInviteList(seed * 5 + 1)
      const b = randomInviteList(seed * 5 + 2)
      const c = randomInviteList(seed * 5 + 3)
      expect(fp(mergeInviteLists(a, b))).toBe(fp(mergeInviteLists(b, a)))
      expect(fp(mergeInviteLists(mergeInviteLists(a, b), c))).toBe(fp(mergeInviteLists(a, mergeInviteLists(b, c))))
      const ab = mergeInviteLists(a, b)
      expect(fp(mergeInviteLists(ab, ab))).toBe(fp(ab))
      // no tombstoned token ever survives, no matter the direction
      const merged = mergeInviteLists(mergeInviteLists(a, b), c)
      const tombs = new Set(merged.tombstones.map(t => t.token))
      for (const e of merged.entries) expect(tombs.has(e.token)).toBe(false)
    }
  })
})

// ---- banlist re-heal -----------------------------------------------------------------------

describe('stress — banlist re-heal convergence (CORD-04 §4)', () => {
  it('N admins racing disjoint bans converge to the union within N rounds of re-heal', () => {
    const rand = prng(0xbaba)
    const admins = Array.from({ length: 6 }, (_, i) =>
      Array.from({ length: 3 }, (_, j) => `target-${i}-${j}`.padEnd(64, '0')),
    )
    // the wire holds ONE replaced document; each round, one racing admin "wins"
    let head: string[] = []
    let healing = true
    let rounds = 0
    while (healing && rounds < 20) {
      healing = false
      rounds++
      for (const mine of shuffled(admins, rand)) {
        const healed = rehealBanlist(head, mine)
        if (healed) {
          head = healed // their re-publish becomes the new head
          healing = true
        }
      }
    }
    const union = new Set(admins.flat())
    expect(new Set(head)).toEqual(union) // never permanently short a ban
    expect(rounds).toBeLessThanOrEqual(admins.length + 1)
  })
})
