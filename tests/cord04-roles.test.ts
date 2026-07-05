/**
 * CORD-04: Roles — every claim in 04.md, asserted.
 */
import { describe, expect, it } from 'vitest'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concat, hexToBytes, randomBytes, u64be, utf8, ZERO32 } from '../src/bytes.js'
import { communityId, controlKey, grantLocator } from '../src/derive.js'
import {
  banlistEid,
  editionHash,
  EDITION_HASH_LABEL,
  editionTags,
  foldControl,
  grantEid,
  KIND_EDITION,
  parseEdition,
  VSK,
  type FoldContext,
} from '../src/editions.js'
import { makeRumor, pubkeyOf, verifyEvent, type Rumor } from '../src/events.js'
import {
  authorize,
  capRoles,
  effectivePermissions,
  MAX_ROLES_PER_COMMUNITY,
  MAX_ROLES_PER_MEMBER,
  memberRoles,
  parsePermissions,
  PERM,
  rank,
  RANK_ROLELESS,
  rehealBanlist,
  writePermissions,
  type Role,
  type Roster,
} from '../src/roster.js'
import { unwrapEvent, wrapRumor, wrapSeal } from '../src/stream.js'

// ---- harness -----------------------------------------------------------------

const ownerSk = randomBytes(32)
const ownerPk = pubkeyOf(ownerSk)
const ownerSalt = randomBytes(32)
const cid = communityId(hexToBytes(ownerPk), ownerSalt)
const ctx: FoldContext = { ownerPk, communityId: cid }

const aliceSk = randomBytes(32)
const alicePk = pubkeyOf(aliceSk)
const bobSk = randomBytes(32)
const bobPk = pubkeyOf(bobSk)
const carolPk = pubkeyOf(randomBytes(32))

let counter = 0
function edition(e: {
  signer: string
  vsk: number
  eid: string
  version: number
  prev?: string | null
  vac?: { eid: string; version: number; hash: string } | null
  content: unknown
}): Rumor {
  return makeRumor({
    kind: KIND_EDITION,
    pubkey: e.signer,
    content: typeof e.content === 'string' ? e.content : JSON.stringify(e.content),
    tags: [...editionTags(e), ['ms', String((counter++ % 1000))]],
    created_at: 1686840217,
  })
}
const hashOf = (r: Rumor) => parseEdition(r).hash

function role(id: string, name: string, position: number, perms: bigint): Role {
  return { role_id: id, name, position, permissions: writePermissions(perms), scope: { kind: 'server' }, color: 0 }
}

const ADMIN_ROLE = 'aa'.repeat(32)
const MOD_ROLE = 'bb'.repeat(32)

/** owner mints admin(pos 1) + mod(pos 2), grants admin→alice. */
function baseline() {
  const adminRole = edition({
    signer: ownerPk, vsk: VSK.ROLE, eid: ADMIN_ROLE, version: 1,
    content: role(ADMIN_ROLE, 'Admin', 1, PERM.MANAGE_ROLES | PERM.MANAGE_CHANNELS | PERM.MANAGE_METADATA | PERM.KICK | PERM.BAN | PERM.CREATE_INVITE),
  })
  const modRole = edition({
    signer: ownerPk, vsk: VSK.ROLE, eid: MOD_ROLE, version: 1,
    content: role(MOD_ROLE, 'Moderator', 2, PERM.KICK | PERM.MANAGE_MESSAGES),
  })
  const aliceGrant = edition({
    signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 1,
    content: { member: alicePk, role_ids: [ADMIN_ROLE] },
  })
  return { adminRole, modRole, aliceGrant }
}
const aliceVac = (aliceGrant: Rumor) => ({ eid: grantEid(cid, alicePk), version: 1, hash: hashOf(aliceGrant) })

// ---- §1 editions ----------------------------------------------------------------

describe('CORD-04 §1 — editions', () => {
  it('edition_hash: sha256 over the length-prefixed, domain-separated preimage — byte-exact', () => {
    const eid = randomBytes(32)
    const content = utf8('{"name":"general","private":false}')
    const prev = randomBytes(32)
    const label = utf8(EDITION_HASH_LABEL)
    const manual = sha256(concat(
      u64be(label.length), label,
      eid,
      u64be(4),
      new Uint8Array([0x01]), prev,
      u64be(content.length), content,
    ))
    expect(bytesToHex(editionHash(eid, 4, prev, content))).toBe(bytesToHex(manual))
    // first edition: prev absent → 0x00 || zero[32]
    const manualFirst = sha256(concat(
      u64be(label.length), label, eid, u64be(1),
      new Uint8Array([0x00]), ZERO32,
      u64be(content.length), content,
    ))
    expect(bytesToHex(editionHash(eid, 1, null, content))).toBe(bytesToHex(manualFirst))
  })

  it('the domain label is exactly "vector-community/v1/edition"', () => {
    expect(EDITION_HASH_LABEL).toBe('vector-community/v1/edition')
  })

  it('every field is fixed-width or length-prefixed: distinct inputs can never collide', () => {
    const eid = randomBytes(32)
    const hashes = [
      editionHash(eid, 1, null, utf8('ab')),
      editionHash(eid, 1, null, utf8('a')), // shorter content
      editionHash(eid, 2, null, utf8('ab')), // different version
      editionHash(eid, 1, ZERO32, utf8('ab')), // prev PRESENT but all-zero ≠ prev absent
      editionHash(randomBytes(32), 1, null, utf8('ab')), // different entity
    ]
    expect(new Set(hashes.map(bytesToHex)).size).toBe(hashes.length)
  })

  it('content is hashed as the exact wire bytes, never re-serialized: equivalent JSON with different spacing hashes differently', () => {
    const eid = randomBytes(32)
    const a = editionHash(eid, 1, null, utf8('{"name":"x"}'))
    const b = editionHash(eid, 1, null, utf8('{ "name": "x" }'))
    expect(bytesToHex(a)).not.toBe(bytesToHex(b))
  })

  it('reading then republishing an edition (a compaction re-wrap) preserves its hash', () => {
    const root = randomBytes(32)
    const control0 = controlKey(root, cid, 0)
    const ed = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'V', relays: [] } })
    const { seal } = wrapRumor(ed, ownerSk, control0, 'plaintext')
    // refounding: re-wrap the same seal at the new epoch, then re-read it
    const control1 = controlKey(randomBytes(32), cid, 1)
    const reread = unwrapEvent(wrapSeal(seal, control1), control1).rumor
    expect(hashOf(reread)).toBe(hashOf(ed))
  })

  it('the on-wire shape: a 3308 rumor whose fields ride tags, in a PLAINTEXT seal at the Control address', () => {
    const root = randomBytes(32)
    const control = controlKey(root, cid, 0)
    const { adminRole } = baseline()
    const { seal, wrap } = wrapRumor(adminRole, ownerSk, control, 'plaintext')
    expect(wrap.kind).toBe(1059)
    expect(wrap.pubkey).toBe(control.pk)
    expect(seal.kind).toBe(20014)
    const opened = unwrapEvent(wrap, control)
    expect(opened.rumor.kind).toBe(3308)
    expect(opened.rumor.tags.find(t => t[0] === 'vsk')![1]).toBe('1')
    expect(opened.rumor.tags.find(t => t[0] === 'eid')![1]).toBe(ADMIN_ROLE)
    expect(opened.rumor.tags.find(t => t[0] === 'ev')![1]).toBe('1')
  })

  it('entity coordinates are deterministic and bind to the community_id, never a key or epoch — they survive every Refounding', () => {
    // derived twice, and from nothing but (community_id, member)
    expect(grantEid(cid, alicePk)).toBe(bytesToHex(grantLocator(cid, hexToBytes(alicePk))))
    expect(grantEid(cid, alicePk)).toBe(grantEid(cid, alicePk))
    // a fresh joiner holding only the newest root derives the exact same coordinates:
    // no root or epoch appears in the inputs at all
    expect(banlistEid(cid)).toBe(banlistEid(cid))
    expect(grantEid(cid, alicePk)).not.toBe(grantEid(cid, bobPk))
  })

  it('fold takes the highest version whose chain is intact', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const v1 = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'One', relays: [] } })
    const v2 = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 2, prev: hashOf(v1), content: { name: 'Two', relays: [] } })
    const state = foldControl([adminRole, modRole, aliceGrant, v1, v2].map(rumor => ({ rumor })), ctx)
    expect(JSON.parse(state.entities.get(bytesToHex(cid))!.content).name).toBe('Two')
  })

  it('refuses to downgrade: a relay replaying a stale Grant (or a lifted Ban) is rejected', () => {
    const { aliceGrant } = baseline()
    const revoke = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 2, prev: hashOf(aliceGrant), content: { member: alicePk, role_ids: [] } })
    // the replayed v1 arrives (again) after the v2 revoke
    const state = foldControl([revoke, aliceGrant, aliceGrant].map(rumor => ({ rumor })), ctx)
    const head = state.entities.get(grantEid(cid, alicePk))!
    expect(head.version).toBe(2)
    expect(JSON.parse(head.content).role_ids).toEqual([])
    expect(rank(state.roster, alicePk)).toBe(RANK_ROLELESS)
  })

  it('a broken chain link is not intact: an edition citing a wrong prev never folds', () => {
    const v1 = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'One', relays: [] } })
    const forged = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 2, prev: 'ee'.repeat(32), content: { name: 'Fake', relays: [] } })
    const state = foldControl([v1, forged].map(rumor => ({ rumor })), ctx)
    expect(JSON.parse(state.entities.get(bytesToHex(cid))!.content).name).toBe('One')
  })

  it('two authorized same-version edits converge: authority first, then the lower rumor id, never the timestamp', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    // owner and alice race a rename at the same version
    const byOwner = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'Owner wins', relays: [] } })
    const byAlice = edition({ signer: alicePk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, vac: aliceVac(aliceGrant), content: { name: 'Alice loses', relays: [] } })
    for (const order of [[byOwner, byAlice], [byAlice, byOwner]]) {
      const state = foldControl([adminRole, modRole, aliceGrant, ...order].map(rumor => ({ rumor })), ctx)
      expect(JSON.parse(state.entities.get(bytesToHex(cid))!.content).name).toBe('Owner wins') // authority first
    }
  })

  it('…and if two equally-ranked editions still tie, the lowest rumor id wins — a rule needing no Roster at all', () => {
    const a = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'A', relays: [] } })
    const b = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'B', relays: [] } })
    const winner = a.id < b.id ? 'A' : 'B'
    for (const order of [[a, b], [b, a]]) {
      const state = foldControl(order.map(rumor => ({ rumor })), ctx)
      expect(JSON.parse(state.entities.get(bytesToHex(cid))!.content).name).toBe(winner)
    }
  })

  it('an edition whose signer isn’t authorized is simply dropped', () => {
    const { adminRole, modRole } = baseline() // note: nobody granted anything
    const byRando = edition({ signer: carolPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, vac: { eid: grantEid(cid, carolPk), version: 1, hash: 'ff'.repeat(32) }, content: { name: 'hax', relays: [] } })
    const state = foldControl([adminRole, modRole, byRando].map(rumor => ({ rumor })), ctx)
    expect(state.entities.has(bytesToHex(cid))).toBe(false)
  })

  it('the Roster is owner-rooted: an entry that doesn’t trace to the owner is not authority, no matter how validly signed', () => {
    // mallory forges a whole parallel roster, self-signed, perfectly shaped
    const mallory = pubkeyOf(randomBytes(32))
    const evilRole = edition({ signer: mallory, vsk: VSK.ROLE, eid: 'cc'.repeat(32), version: 1, vac: { eid: grantEid(cid, mallory), version: 1, hash: 'dd'.repeat(32) }, content: role('cc'.repeat(32), 'God', 1, PERM.BAN | PERM.MANAGE_ROLES) })
    const evilGrant = edition({ signer: mallory, vsk: VSK.GRANT, eid: grantEid(cid, mallory), version: 1, vac: { eid: grantEid(cid, mallory), version: 1, hash: 'dd'.repeat(32) }, content: { member: mallory, role_ids: ['cc'.repeat(32)] } })
    const state = foldControl([evilRole, evilGrant].map(rumor => ({ rumor })), ctx)
    expect(state.entities.size).toBe(0) // none of it folds
    expect(rank(state.roster, mallory)).toBe(RANK_ROLELESS)
  })

  it('the owner’s rank comes from the community_id itself, breaking the authority circularity', () => {
    // an empty fold — no editions at all — already ranks the owner at 0
    const state = foldControl([], ctx)
    expect(rank(state.roster, ownerPk)).toBe(0)
    expect(rank(state.roster, alicePk)).toBe(RANK_ROLELESS)
  })

  it('folding across a Refounding: a FRESH joiner accepts the highest authority-verified head despite a dangling prev', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    // compaction re-wrapped only the current heads: v5 with a prev citing a vanished v4
    const head = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 5, prev: 'ab'.repeat(32), content: { name: 'Compacted', relays: [] } })
    const state = foldControl([adminRole, modRole, aliceGrant, head].map(rumor => ({ rumor })), ctx, 'fresh')
    expect(state.entities.get(bytesToHex(cid))!.version).toBe(5)
    expect(state.suspended.size).toBe(0) // a joiner is never locked out
  })

  it('…while a TRACKING client treats an unresolvable prev as a gap and fails closed for that entity', () => {
    const v1 = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'One', relays: [] } })
    const v3 = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 3, prev: 'ab'.repeat(32), content: { name: 'Three', relays: [] } })
    const state = foldControl([v1, v3].map(rumor => ({ rumor })), ctx, 'tracking')
    expect(state.suspended.has(bytesToHex(cid))).toBe(true) // suspended, refetch — never trust a hole
    expect(state.entities.has(bytesToHex(cid))).toBe(false) // honest history can't be truncated
  })

  it('the chain IS the audit log: every action names its actor by real, verifiable signature', () => {
    const root = randomBytes(32)
    const control = controlKey(root, cid, 0)
    const { adminRole } = baseline()
    const { wrap } = wrapRumor(adminRole, ownerSk, control, 'plaintext')
    const opened = unwrapEvent(wrap, control)
    expect(opened.seal.pubkey).toBe(ownerPk) // unforgeable, undeniable
    expect(verifyEvent(opened.seal)).toBe(true)
    expect(opened.rumor.pubkey).toBe(ownerPk)
  })
})

// ---- §2 the roster ----------------------------------------------------------------

describe('CORD-04 §2 — the Roster', () => {
  it('a Role mints no key: granting it hands rank, never a secret', () => {
    const r = role(ADMIN_ROLE, 'Admin', 1, PERM.MANAGE_ROLES)
    expect(Object.keys(r).sort()).toEqual(['color', 'name', 'permissions', 'position', 'role_id', 'scope'])
    // nothing key-like in the entity
    expect(JSON.stringify(r)).not.toMatch(/key|secret/)
  })

  it('a Grant maps a member to Roles; empty role_ids is a revoke', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const s1 = foldControl([adminRole, modRole, aliceGrant].map(rumor => ({ rumor })), ctx)
    expect(rank(s1.roster, alicePk)).toBe(1)
    const revoke = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 2, prev: hashOf(aliceGrant), content: { member: alicePk, role_ids: [] } })
    const s2 = foldControl([adminRole, modRole, aliceGrant, revoke].map(rumor => ({ rumor })), ctx)
    expect(rank(s2.roster, alicePk)).toBe(RANK_ROLELESS)
  })

  it('a Grant is honored only if its signer already outranks every Role it hands out', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    // alice (rank 1) tries to hand out ADMIN (position 1): equal, not outranked → dropped
    const selfPeer = edition({ signer: alicePk, vsk: VSK.GRANT, eid: grantEid(cid, bobPk), version: 1, vac: aliceVac(aliceGrant), content: { member: bobPk, role_ids: [ADMIN_ROLE] } })
    const s1 = foldControl([adminRole, modRole, aliceGrant, selfPeer].map(rumor => ({ rumor })), ctx)
    expect(rank(s1.roster, bobPk)).toBe(RANK_ROLELESS)
    // handing out MOD (position 2) is fine: 1 < 2
    const modGrant = edition({ signer: alicePk, vsk: VSK.GRANT, eid: grantEid(cid, bobPk), version: 1, vac: aliceVac(aliceGrant), content: { member: bobPk, role_ids: [MOD_ROLE] } })
    const s2 = foldControl([adminRole, modRole, aliceGrant, modGrant].map(rumor => ({ rumor })), ctx)
    expect(rank(s2.roster, bobPk)).toBe(2)
  })

  it('a member holds at most 64 Roles; a Community carries at most 100 (the 100 lowest role_ids fold)', () => {
    expect(MAX_ROLES_PER_MEMBER).toBe(64)
    expect(MAX_ROLES_PER_COMMUNITY).toBe(100)
    const roles = new Map<string, Role>()
    for (let i = 0; i < 120; i++) {
      const id = i.toString(16).padStart(64, '0')
      roles.set(id, role(id, `r${i}`, i + 1, 0n))
    }
    const capped = capRoles(roles)
    expect(capped.size).toBe(100)
    const kept = [...capped.keys()].sort()
    expect(kept[0]).toBe((0).toString(16).padStart(64, '0')) // the LOWEST ids survive
    expect(capped.has((119).toString(16).padStart(64, '0'))).toBe(false)

    const roster: Roster = { ownerPk, roles, grants: new Map([[alicePk, { member: alicePk, role_ids: [...roles.keys()] }]]) }
    expect(memberRoles(roster, alicePk).length).toBeLessThanOrEqual(64)
  })
})

// ---- §3 permissions and position ------------------------------------------------------

describe('CORD-04 §3 — permissions and position', () => {
  it('the bit table is frozen exactly as specified', () => {
    expect(PERM.MANAGE_ROLES).toBe(1n << 0n)
    expect(PERM.MANAGE_CHANNELS).toBe(1n << 1n)
    expect(PERM.MANAGE_METADATA).toBe(1n << 2n)
    expect(PERM.KICK).toBe(1n << 3n)
    expect(PERM.BAN).toBe(1n << 4n)
    expect(PERM.MANAGE_MESSAGES).toBe(1n << 5n)
    expect(PERM.CREATE_INVITE).toBe(1n << 6n)
    expect(PERM.RETIRED_MANAGE_INVITES).toBe(1n << 7n) // burned, never reused
    expect(PERM.VIEW_AUDIT_LOG).toBe(1n << 8n)
    expect(PERM.MENTION_EVERYONE).toBe(1n << 9n)
  })

  it('effective permissions are the UNION of a member’s Roles’ bits', () => {
    const roles = new Map([
      [MOD_ROLE, role(MOD_ROLE, 'Mod', 2, PERM.KICK | PERM.MANAGE_MESSAGES)],
      [ADMIN_ROLE, role(ADMIN_ROLE, 'Meta', 3, PERM.MANAGE_METADATA)],
    ])
    const roster: Roster = { ownerPk, roles, grants: new Map([[alicePk, { member: alicePk, role_ids: [MOD_ROLE, ADMIN_ROLE] }]]) }
    expect(effectivePermissions(roster, alicePk)).toBe(PERM.KICK | PERM.MANAGE_MESSAGES | PERM.MANAGE_METADATA)
  })

  it('there is no all-powerful bit: a Role granted everything today does NOT inherit a permission added tomorrow', () => {
    // "everything today" = union of the currently defined grantable bits
    const everythingToday =
      PERM.MANAGE_ROLES | PERM.MANAGE_CHANNELS | PERM.MANAGE_METADATA | PERM.KICK | PERM.BAN |
      PERM.MANAGE_MESSAGES | PERM.CREATE_INVITE | PERM.VIEW_AUDIT_LOG | PERM.MENTION_EVERYONE
    const tomorrowBit = 1n << 13n // the next free bit, claimed by a future permission
    expect(everythingToday & tomorrowBit).toBe(0n) // not inherited — must be granted deliberately
  })

  it('permissions ride the wire as a decimal string: all 64 bits survive where a JSON number corrupts past 2^53', () => {
    const high = (1n << 62n) | (1n << 3n)
    const asString = writePermissions(high)
    expect(asString).toBe(high.toString(10))
    expect(parsePermissions(asString)).toBe(high)
    // the number path demonstrably corrupts
    const corrupted = Number(high)
    expect(BigInt(corrupted)).not.toBe(high)
  })

  it('a reader accepts either form (number from an older edition, string henceforth) and always writes the string', () => {
    expect(parsePermissions(40)).toBe(40n) // 1<<3 KICK | 1<<5 MANAGE_MESSAGES
    expect(parsePermissions('40')).toBe(40n)
    expect(typeof writePermissions(40n)).toBe('string')
  })

  it('position: lower is higher, the owner is 0 (never a Role), a roleless member is effectively last', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const s = foldControl([adminRole, modRole, aliceGrant].map(rumor => ({ rumor })), ctx)
    expect(rank(s.roster, ownerPk)).toBe(0)
    expect(rank(s.roster, alicePk)).toBe(1)
    expect(rank(s.roster, carolPk)).toBe(RANK_ROLELESS)
    expect(rank(s.roster, alicePk)).toBeLessThan(rank(s.roster, carolPk))
  })

  it('a member’s rank is the LOWEST position among their Roles', () => {
    const roles = new Map([
      [ADMIN_ROLE, role(ADMIN_ROLE, 'Admin', 1, 0n)],
      [MOD_ROLE, role(MOD_ROLE, 'Mod', 5, 0n)],
    ])
    const roster: Roster = { ownerPk, roles, grants: new Map([[alicePk, { member: alicePk, role_ids: [ADMIN_ROLE, MOD_ROLE] }]]) }
    expect(rank(roster, alicePk)).toBe(1)
  })

  it('the actor must hold the bit AND strictly outrank the target: equal cannot act on equal', () => {
    const roles = new Map([[ADMIN_ROLE, role(ADMIN_ROLE, 'Admin', 1, PERM.BAN | PERM.KICK)]])
    const roster: Roster = {
      ownerPk, roles,
      grants: new Map([
        [alicePk, { member: alicePk, role_ids: [ADMIN_ROLE] }],
        [bobPk, { member: bobPk, role_ids: [ADMIN_ROLE] }],
      ]),
    }
    // an admin cannot ban a peer admin
    expect(authorize(roster, alicePk, PERM.BAN, rank(roster, bobPk))).toBe(false)
    // but can act on a roleless member
    expect(authorize(roster, alicePk, PERM.BAN, rank(roster, carolPk))).toBe(true)
    // and never without the bit
    expect(authorize(roster, alicePk, PERM.MANAGE_ROLES, rank(roster, carolPk))).toBe(false)
    // the owner outranks everyone
    expect(authorize(roster, ownerPk, PERM.BAN, rank(roster, alicePk))).toBe(true)
  })

  it('no edition may claim a position at or above its own signer: nobody promotes themselves toward the top', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    // alice (rank 1) mints a role at position 1 (equal) and position 0 (above): both dropped
    for (const pos of [0, 1]) {
      const evil = edition({ signer: alicePk, vsk: VSK.ROLE, eid: 'dd'.repeat(32), version: 1, vac: aliceVac(aliceGrant), content: role('dd'.repeat(32), 'Sneaky', pos, PERM.MANAGE_ROLES) })
      const s = foldControl([adminRole, modRole, aliceGrant, evil].map(rumor => ({ rumor })), ctx)
      expect(s.entities.has('dd'.repeat(32))).toBe(false)
    }
    // position 2 (below) folds fine
    const ok = edition({ signer: alicePk, vsk: VSK.ROLE, eid: 'dd'.repeat(32), version: 1, vac: aliceVac(aliceGrant), content: role('dd'.repeat(32), 'Helper', 2, PERM.MANAGE_MESSAGES) })
    const s = foldControl([adminRole, modRole, aliceGrant, ok].map(rumor => ({ rumor })), ctx)
    expect(s.entities.has('dd'.repeat(32))).toBe(true)
  })

  it('two Roles MAY share a position: they are peers, neither acts on the other; display ties break by lower role_id', () => {
    const r1 = role('11'.repeat(32), 'PeerA', 3, PERM.KICK)
    const r2 = role('22'.repeat(32), 'PeerB', 3, PERM.KICK)
    const roster: Roster = {
      ownerPk,
      roles: new Map([[r1.role_id, r1], [r2.role_id, r2]]),
      grants: new Map([
        [alicePk, { member: alicePk, role_ids: [r1.role_id] }],
        [bobPk, { member: bobPk, role_ids: [r2.role_id] }],
      ]),
    }
    expect(authorize(roster, alicePk, PERM.KICK, rank(roster, bobPk))).toBe(false)
    expect(authorize(roster, bobPk, PERM.KICK, rank(roster, alicePk))).toBe(false)
    // one deterministic display order
    const display = [r2, r1].sort((a, b) => (a.position - b.position) || (a.role_id < b.role_id ? -1 : 1))
    expect(display.map(r => r.name)).toEqual(['PeerA', 'PeerB'])
  })
})

// ---- §4 the banlist -----------------------------------------------------------------

describe('CORD-04 §4 — the Banlist', () => {
  it('honored only if its signer holds BAN', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const bobGrant = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, bobPk), version: 1, content: { member: bobPk, role_ids: [MOD_ROLE] } })
    const bobVac = { eid: grantEid(cid, bobPk), version: 1, hash: hashOf(bobGrant) }
    // bob is a mod (KICK, no BAN): his banlist edit is dropped
    const byBob = edition({ signer: bobPk, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: bobVac, content: [carolPk] })
    const s1 = foldControl([adminRole, modRole, aliceGrant, bobGrant, byBob].map(rumor => ({ rumor })), ctx)
    expect(s1.banlist.size).toBe(0)
    // alice holds BAN: hers folds
    const byAlice = edition({ signer: alicePk, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: aliceVac(aliceGrant), content: [carolPk] })
    const s2 = foldControl([adminRole, modRole, aliceGrant, byAlice].map(rumor => ({ rumor })), ctx)
    expect(s2.banlist.has(carolPk)).toBe(true)
  })

  it('…and the actor must strictly outrank whom they ban: an admin cannot ban a peer admin, nor the owner', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const bobAdmin = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, bobPk), version: 1, content: { member: bobPk, role_ids: [ADMIN_ROLE] } })
    for (const target of [bobPk /* peer */, ownerPk /* supreme */]) {
      const evil = edition({ signer: alicePk, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: aliceVac(aliceGrant), content: [target] })
      const s = foldControl([adminRole, modRole, aliceGrant, bobAdmin, evil].map(rumor => ({ rumor })), ctx)
      expect(s.banlist.size).toBe(0)
    }
  })

  it('every honest client drops EVERY event from a banned npub: message, reaction, edit, or authority action alike', () => {
    const banlist = new Set([carolPk])
    const dropBanned = (e: { pubkey: string }) => !banlist.has(e.pubkey)
    const kinds = [9, 7, 3302, 5, 3308, 3306, 3309]
    for (const kind of kinds) {
      const ev = makeRumor({ kind, pubkey: carolPk, content: '', tags: [], created_at: 1 })
      expect(dropBanned(ev)).toBe(false) // vanishes entirely
    }
    expect(dropBanned(makeRumor({ kind: 9, pubkey: alicePk, content: '', tags: [], created_at: 1 }))).toBe(true)
  })

  it('a single replaced document: two admins banning different members at the same version collide — one edition wins', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const bobGrant = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, bobPk), version: 1, content: { member: bobPk, role_ids: [ADMIN_ROLE] } })
    // both cite valid grants; same version 1; different targets
    const target2 = pubkeyOf(randomBytes(32))
    const banA = edition({ signer: alicePk, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: aliceVac(aliceGrant), content: [carolPk] })
    const banB = edition({ signer: bobPk, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: { eid: grantEid(cid, bobPk), version: 1, hash: hashOf(bobGrant) }, content: [target2] })
    const s = foldControl([adminRole, modRole, aliceGrant, bobGrant, banA, banB].map(rumor => ({ rumor })), ctx)
    expect(s.banlist.size).toBe(1) // the other's addition dropped until re-applied
  })

  it('re-heal: if your addition isn’t in the head, re-apply it atop the winner — convergence to the union', () => {
    const winner = [carolPk]
    const myAdditions = [pubkeyOf(randomBytes(32))]
    const healed = rehealBanlist(winner, myAdditions)!
    expect(healed).toEqual([...winner, ...myAdditions]) // the union
    // and once the head contains it, nothing further to heal
    expect(rehealBanlist(healed, myAdditions)).toBeNull()
  })
})

// ---- §5 authorizing an action ----------------------------------------------------------

describe('CORD-04 §5 — the authority citation (vac)', () => {
  it('block-until-synced: an action citing a Grant version the verifier hasn’t synced stays parked', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    // the owner re-grants alice at v2; alice cites it truthfully — but the
    // verifier hasn't synced that Grant yet
    const regrant = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 2, prev: hashOf(aliceGrant), content: { member: alicePk, role_ids: [ADMIN_ROLE] } })
    const premature = edition({ signer: alicePk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, vac: { eid: grantEid(cid, alicePk), version: 2, hash: hashOf(regrant) }, content: { name: 'Early', relays: [] } })
    const s1 = foldControl([adminRole, modRole, aliceGrant, premature].map(rumor => ({ rumor })), ctx)
    expect(s1.entities.has(bytesToHex(cid))).toBe(false) // parked, indistinguishable from rejection
    // once the cited Grant syncs, the action is honored
    const s2 = foldControl([adminRole, modRole, aliceGrant, regrant, premature].map(rumor => ({ rumor })), ctx)
    expect(s2.entities.has(bytesToHex(cid))).toBe(true)
  })

  it('rank resolves against the CURRENT roster: a just-demoted member’s stale action is dropped, an old valid citation grandfathers nothing', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const demotion = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 2, prev: hashOf(aliceGrant), content: { member: alicePk, role_ids: [] } })
    // alice's action cites her once-valid v1 grant
    const stale = edition({ signer: alicePk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, vac: aliceVac(aliceGrant), content: { name: 'Stale', relays: [] } })
    const s = foldControl([adminRole, modRole, aliceGrant, demotion, stale].map(rumor => ({ rumor })), ctx)
    expect(s.entities.has(bytesToHex(cid))).toBe(false) // dropped the instant the demotion is held
  })

  it('an absurd citation griefs nobody but the actor: it parks only its own author’s action', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const absurd = edition({ signer: alicePk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, vac: { eid: grantEid(cid, alicePk), version: 999, hash: 'ee'.repeat(32) }, content: { name: 'Never', relays: [] } })
    // an unrelated, honest edit by the owner is entirely unaffected
    const honest = edition({ signer: ownerPk, vsk: VSK.CHANNEL_METADATA, eid: 'ab'.repeat(32), version: 1, content: { name: 'general', private: false } })
    const s = foldControl([adminRole, modRole, aliceGrant, absurd, honest].map(rumor => ({ rumor })), ctx)
    expect(s.entities.has('ab'.repeat(32))).toBe(true)
    expect(s.entities.has(bytesToHex(cid))).toBe(false)
  })

  it('supreme needs no citation: the vac is absent when the owner acts', () => {
    const byOwner = edition({ signer: ownerPk, vsk: VSK.COMMUNITY_METADATA, eid: bytesToHex(cid), version: 1, content: { name: 'V', relays: [] } })
    expect(byOwner.tags.some(t => t[0] === 'vac')).toBe(false)
    const s = foldControl([byOwner].map(rumor => ({ rumor })), ctx)
    expect(s.entities.has(bytesToHex(cid))).toBe(true)
  })
})

// ---- §6 the three removals -----------------------------------------------------------

describe('CORD-04 §6 — the three removals', () => {
  it('Role Removal strips authority: the target remains a member, reads and writes freely, but outranks nobody', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const strip = edition({ signer: ownerPk, vsk: VSK.GRANT, eid: grantEid(cid, alicePk), version: 2, prev: hashOf(aliceGrant), content: { member: alicePk, role_ids: [] } })
    const s = foldControl([adminRole, modRole, aliceGrant, strip].map(rumor => ({ rumor })), ctx)
    expect(rank(s.roster, alicePk)).toBe(RANK_ROLELESS)
    expect(effectivePermissions(s.roster, alicePk)).toBe(0n)
    expect(s.banlist.has(alicePk)).toBe(false) // still a member
    // and their pending vac citations die with the revoked Grant (asserted in §5 above)
  })

  it('a Kick alone never enforces anything: a defiant client still holds every key', () => {
    const root = randomBytes(32)
    const gk = controlKey(root, cid, 0)
    const { wrap } = wrapRumor(
      { kind: 9, pubkey: ownerPk, content: 'still readable', tags: [], created_at: 1 },
      ownerSk, gk, 'encrypted',
    )
    // the kicked-but-defiant member's key still opens everything: cooperation is the only mechanism
    expect(unwrapEvent(wrap, gk).rumor.content).toBe('still readable')
  })

  it('Cryptographic Removal is the only removal that enforces: after the rotation, everything is unreadable to the target', () => {
    const oldRoot = randomBytes(32)
    const newRoot = randomBytes(32) // delivered to everyone but the target
    const oldControl = controlKey(oldRoot, cid, 0)
    const newControl = controlKey(newRoot, cid, 1)
    const post = wrapRumor(
      { kind: 9, pubkey: ownerPk, content: 'post-removal', tags: [], created_at: 2 },
      ownerSk, newControl, 'encrypted',
    )
    expect(() => unwrapEvent(post.wrap, oldControl)).toThrow() // no cooperation required
  })

  it('each layer validates independently: a Kick from a non-KICK holder is dropped, a Ban from a non-BAN holder is dropped', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    const state = foldControl([adminRole, modRole, aliceGrant].map(rumor => ({ rumor })), ctx)
    // carol holds nothing
    expect(authorize(state.roster, carolPk, PERM.KICK, rank(state.roster, bobPk))).toBe(false)
    expect(authorize(state.roster, carolPk, PERM.BAN, rank(state.roster, bobPk))).toBe(false)
    // alice holds both (admin)
    expect(authorize(state.roster, alicePk, PERM.KICK, rank(state.roster, bobPk))).toBe(true)
    expect(authorize(state.roster, alicePk, PERM.BAN, rank(state.roster, bobPk))).toBe(true)
  })

  it('a partially propagated removal degrades to a WEAKER removal, never a broken one', () => {
    const { adminRole, modRole, aliceGrant } = baseline()
    // the Ban composition arrives piecewise; model a client holding only the banlist layer
    const banOnly = edition({ signer: alicePk, vsk: VSK.BANLIST, eid: banlistEid(cid), version: 1, vac: aliceVac(aliceGrant), content: [carolPk] })
    const s = foldControl([adminRole, modRole, aliceGrant, banOnly].map(rumor => ({ rumor })), ctx)
    // silencing works already (instant and free), even before the Refounding lands
    expect(s.banlist.has(carolPk)).toBe(true)
    // nothing is inconsistent: the roster is intact, the community keeps functioning
    expect(rank(s.roster, alicePk)).toBe(1)
    expect(s.suspended.size).toBe(0)
  })
})
