/**
 * CORD-04 §1 — Editions: the versioned, chained, authority-checked units of
 * Control Plane state, and the fold that turns them into current state.
 */
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concat, hexToBytes, u64be, utf8, ZERO32 } from './bytes.js'
import { banlistLocator, grantLocator, inviteLinksLocator } from './derive.js'
import { tag, tagValue, type Rumor } from './events.js'
import {
  effectivePermissions,
  PERM,
  rank,
  type Grant,
  type Role,
  type Roster,
} from './roster.js'

export const KIND_EDITION = 3308

export const VSK = {
  COMMUNITY_METADATA: 0,
  ROLE: 1,
  CHANNEL_METADATA: 2,
  GRANT: 3,
  BANLIST: 4,
  RESERVED_ROLE_ORDER: 5,
  INVITE_LIVE: 6, // claimed by the addressable invite marker (kind 33301)
  RETIRED_OWNER_ATTESTATION: 7,
  INVITE_REGISTRY: 8,
  INVITE_TOMBSTONE: 9, // claimed by the addressable invite marker (kind 33301)
  DISSOLVED: 10, // chainless, exempt from version discipline
} as const

export const EDITION_HASH_LABEL = 'vector-community/v1/edition'

/**
 * §1 — edition_hash: sha256 over a length-prefixed, domain-separated preimage.
 * `content` is hashed as the exact bytes on the wire, never re-serialized.
 */
export function editionHash(
  entityId: Uint8Array,
  version: number | bigint,
  prev: Uint8Array | null,
  contentBytes: Uint8Array,
): Uint8Array {
  if (entityId.length !== 32) throw new Error('entity_id must be 32 bytes')
  const label = utf8(EDITION_HASH_LABEL)
  const prevPart = prev
    ? concat(new Uint8Array([0x01]), prev)
    : concat(new Uint8Array([0x00]), ZERO32)
  if (prev && prev.length !== 32) throw new Error('prev must be 32 bytes')
  return sha256(
    concat(
      u64be(label.length),
      label,
      entityId,
      u64be(version),
      prevPart,
      u64be(contentBytes.length),
      utf8FromBytes(contentBytes),
    ),
  )
}
// content bytes pass through untouched; helper keeps types honest
function utf8FromBytes(b: Uint8Array): Uint8Array {
  return b
}

export interface Edition {
  rumor: Rumor // kind 3308; rumor.pubkey is the actor's real npub (seal-verified)
  vsk: number
  eid: string // hex
  version: number
  prev: string | null // hex edition hash of the superseded edition
  vac: { eid: string; version: number; hash: string } | null
  content: string // exact wire bytes
  hash: string // this edition's hash (hex)
}

export function parseEdition(rumor: Rumor): Edition {
  if (rumor.kind !== KIND_EDITION) throw new Error('not a kind 3308 edition')
  const vsk = Number(tagValue(rumor, 'vsk'))
  const eid = tagValue(rumor, 'eid')!
  const version = Number(tagValue(rumor, 'ev') ?? '0')
  const prev = tagValue(rumor, 'ep') ?? null
  const vacTag = tag(rumor, 'vac')
  const vac = vacTag
    ? { eid: vacTag[1]!, version: Number(vacTag[2]!), hash: vacTag[3]! }
    : null
  const hash = bytesToHex(
    editionHash(
      hexToBytes(eid),
      version,
      prev ? hexToBytes(prev) : null,
      utf8(rumor.content),
    ),
  )
  return { rumor, vsk, eid, version, prev, vac, content: rumor.content, hash }
}

/** Build the tags for an edition rumor. */
export function editionTags(e: {
  vsk: number
  eid: string
  version?: number
  prev?: string | null
  vac?: { eid: string; version: number; hash: string } | null
}): string[][] {
  const tags: string[][] = [
    ['vsk', String(e.vsk)],
    ['eid', e.eid],
  ]
  if (e.version !== undefined) tags.push(['ev', String(e.version)])
  if (e.prev) tags.push(['ep', e.prev])
  if (e.vac) tags.push(['vac', e.vac.eid, String(e.vac.version), e.vac.hash])
  return tags
}

export interface AcceptedEdition extends Edition {
  signer: string
}

export interface ControlState {
  entities: Map<string, AcceptedEdition> // by eid — the current head per entity
  suspended: Set<string> // tracking-mode fail-closed entities (unresolvable prev)
  roster: Roster
  banlist: Set<string>
}

export interface FoldContext {
  ownerPk: string
  communityId: Uint8Array
}

/** Rebuild the Roster (roles + grants) from the currently accepted heads. */
function rosterFrom(ctx: FoldContext, accepted: Map<string, AcceptedEdition>): Roster {
  const roles = new Map<string, Role>()
  const grants = new Map<string, Grant>()
  for (const head of accepted.values()) {
    if (head.vsk === VSK.ROLE) {
      const r = JSON.parse(head.content) as Role
      roles.set(r.role_id, r)
    } else if (head.vsk === VSK.GRANT) {
      const g = JSON.parse(head.content) as Grant
      grants.set(g.member, g)
    }
  }
  return { ownerPk: ctx.ownerPk, roles, grants }
}

function banlistFrom(accepted: Map<string, AcceptedEdition>, ctx: FoldContext): Set<string> {
  const eid = bytesToHex(banlistLocator(ctx.communityId))
  const head = accepted.get(eid)
  if (!head) return new Set()
  return new Set(JSON.parse(head.content) as string[])
}

/** The permission bit each vsk's edit requires. */
function requiredBit(vsk: number): bigint | null {
  switch (vsk) {
    case VSK.COMMUNITY_METADATA:
      return PERM.MANAGE_METADATA
    case VSK.ROLE:
      return PERM.MANAGE_ROLES
    case VSK.CHANNEL_METADATA:
      return PERM.MANAGE_CHANNELS
    case VSK.GRANT:
      return PERM.MANAGE_ROLES
    case VSK.BANLIST:
      return PERM.BAN
    case VSK.INVITE_REGISTRY:
      return PERM.CREATE_INVITE
    default:
      return null // unknown / non-editable vsk: never authorized
  }
}

/**
 * Is this edition authorized under the given roster?
 * - signer must hold the required bit and strictly outrank its target,
 * - a Role edition may not claim a position at or above its own signer
 *   (this binds EVERY signer, the owner included: the owner is position 0,
 *   so no Role may ever claim position 0 — the top is not mintable),
 * - a Grant's signer must outrank every Role it hands out (and its target),
 * - the vac is a sync floor pinned by coordinate, version, AND content hash:
 *   the cited Grant must be synced to at least the cited version, the cited
 *   hash must match what we hold there, and rank resolves against the
 *   CURRENT roster,
 * - the owner is supreme and needs no citation.
 */
function isAuthorized(
  ed: AcceptedEdition,
  roster: Roster,
  ctx: FoldContext,
  synced: Map<string, number>, // eid → highest version we hold
  syncedHashes: Map<string, Set<string>>, // `${eid}:${version}` → edition hashes we hold
  accepted: Map<string, AcceptedEdition>,
): boolean {
  const signer = ed.signer
  if (signer === ctx.ownerPk) {
    // supreme needs no citation — but the position rule still binds:
    if (ed.vsk === VSK.ROLE) {
      const role = JSON.parse(ed.content) as Role
      if (!Number.isInteger(role.position) || role.position <= 0) return false
    }
    return true
  }

  // vac sync floor — block-until-synced
  if (!ed.vac) return false // a non-owner authority action cites the Grant it acts under
  const have = synced.get(ed.vac.eid) ?? 0
  if (have < ed.vac.version) return false // parked, not honored
  // the citation is pinned by content hash too: if we hold editions at the
  // cited version and none carries the cited hash, the citation is a forgery
  // (or a fork) and the action parks exactly like an unsynced one
  const held = syncedHashes.get(`${ed.vac.eid}:${ed.vac.version}`)
  if (held && !held.has(ed.vac.hash)) return false

  const bit = requiredBit(ed.vsk)
  if (bit === null) return false
  if ((effectivePermissions(roster, signer) & bit) === 0n) return false
  const signerRank = rank(roster, signer)

  switch (ed.vsk) {
    case VSK.ROLE: {
      const role = JSON.parse(ed.content) as Role
      // no edition may claim a position at or above its own signer
      if (!Number.isInteger(role.position)) return false
      return role.position > signerRank
    }
    case VSK.GRANT: {
      const g = JSON.parse(ed.content) as Grant
      // outrank the target member (equal cannot act on equal)…
      const targetRank = rank(roster, g.member)
      if (!(signerRank < targetRank)) return false
      // …and every Role handed out
      for (const rid of g.role_ids) {
        const role = roster.roles.get(rid)
        if (!role) return false
        if (!(signerRank < role.position)) return false
      }
      return true
    }
    case VSK.BANLIST: {
      // the actor must strictly outrank every member their edit ADDS
      const prevHead = accepted.get(ed.eid)
      const before = new Set(prevHead ? (JSON.parse(prevHead.content) as string[]) : [])
      const after = JSON.parse(ed.content) as string[]
      for (const npub of after) {
        if (before.has(npub)) continue
        if (npub === ctx.ownerPk) return false // the owner is supreme and unremovable
        if (!(signerRank < rank(roster, npub))) return false // equal cannot act on equal
      }
      return true
    }
    default:
      return true // bit held is the whole test for list/metadata entities
  }
}

/**
 * §1 — the fold. Per entity, take the highest version whose chain is intact,
 * refuse to downgrade, and converge deterministically on conflicts
 * (authority first, then the lower rumor id, never the timestamp).
 *
 * mode 'tracking': a client that held the prior chain — an unresolvable prev
 * is a gap; fail closed for that entity.
 * mode 'fresh': a joiner starting from nothing at a new epoch — accept the
 * highest authority-verified head despite a dangling prev.
 */
export function foldControl(
  inputs: { rumor: Rumor }[],
  ctx: FoldContext,
  mode: 'tracking' | 'fresh' = 'tracking',
): ControlState {
  // Garbage tolerance: the fold bounds its own processing — a malformed
  // edition (missing tags, non-hex eid, bad version, unparseable JSON where
  // a structure is required) is skipped, never a crash.
  const editions: AcceptedEdition[] = []
  for (const i of inputs) {
    try {
      const parsed = parseEdition(i.rumor)
      if (!/^[0-9a-f]{64}$/.test(parsed.eid)) continue
      if (!Number.isInteger(parsed.version) || parsed.version < 1) continue
      if (!Number.isInteger(parsed.vsk) || parsed.vsk < 0) continue
      // entity structures must at least parse where the fold reads them
      if ([VSK.ROLE, VSK.GRANT, VSK.BANLIST].includes(parsed.vsk as 1 | 3 | 4)) {
        JSON.parse(parsed.content)
      }
      editions.push({ ...parsed, signer: i.rumor.pubkey })
    } catch {
      continue
    }
  }

  // highest version we hold per entity (the vac sync floor looks at this),
  // plus the edition hashes held at each (eid, version) — the vac's hash pin
  const synced = new Map<string, number>()
  const syncedHashes = new Map<string, Set<string>>()
  for (const e of editions) {
    synced.set(e.eid, Math.max(synced.get(e.eid) ?? 0, e.version))
    const key = `${e.eid}:${e.version}`
    if (!syncedHashes.has(key)) syncedHashes.set(key, new Set())
    syncedHashes.get(key)!.add(e.hash)
  }
  const byEid = new Map<string, AcceptedEdition[]>()
  for (const e of editions) {
    if (!byEid.has(e.eid)) byEid.set(e.eid, [])
    byEid.get(e.eid)!.push(e)
  }

  const accepted = new Map<string, AcceptedEdition>()
  const suspended = new Set<string>()

  /**
   * Fold one set of entities to fixpoint. When `fixedRoster` is given, every
   * authority judgment uses it (the CURRENT roster, per §5); otherwise the
   * roster is re-derived from `accepted` each round (the owner-rooted,
   * resolve-outward bootstrap of §1).
   */
  const runFold = (eids: Set<string>, fixedRoster?: Roster) => {
    let changed = true
    let guard = 0
    while (changed) {
      if (guard++ > 10_000) throw new Error('fold did not converge')
      changed = false
      const roster = fixedRoster ?? rosterFrom(ctx, accepted)

      for (const [eid, list] of byEid) {
        if (!eids.has(eid)) continue
        if (suspended.has(eid)) continue
        const head = accepted.get(eid)
        const headVersion = head?.version ?? 0

        // candidates strictly above the current head — refuse to downgrade
        const above = list.filter(e => e.version > headVersion)
        if (above.length === 0) continue

        // chain-intact requirement
        const linked = above.filter(e => {
          if (e.version === headVersion + 1) {
            if (headVersion === 0) return e.prev === null || mode === 'fresh'
            return e.prev === head!.hash
          }
          // a version jump: only a fresh joiner baselines a dangling head
          return mode === 'fresh'
        })

        // fresh mode: prefer the highest version on offer
        const maxV = linked.length ? Math.max(...linked.map(e => e.version)) : 0
        const atNext = linked.filter(e =>
          mode === 'fresh' ? e.version === maxV : e.version === headVersion + 1,
        )

        const authorized = atNext.filter(e => {
          try {
            return isAuthorized(e, roster, ctx, synced, syncedHashes, accepted)
          } catch {
            return false // malformed content in an otherwise-shaped edition
          }
        })
        if (authorized.length === 0) {
          // tracking mode: a version jump with no linkable next edition is a gap
          if (
            mode === 'tracking' &&
            above.some(e => e.version > headVersion + 1) &&
            !above.some(e => e.version === headVersion + 1)
          ) {
            suspended.add(eid)
            accepted.delete(eid)
            changed = true
          }
          continue
        }

        // same-version conflict: authority first, then the lower rumor id
        authorized.sort((a, b) => {
          const ra = a.signer === ctx.ownerPk ? 0 : rank(roster, a.signer)
          const rb = b.signer === ctx.ownerPk ? 0 : rank(roster, b.signer)
          if (ra !== rb) return ra - rb
          return a.rumor.id < b.rumor.id ? -1 : a.rumor.id > b.rumor.id ? 1 : 0
        })
        accepted.set(eid, authorized[0]!)
        changed = true
      }
    }
  }

  // Phase 1 — the Roster itself (Roles + Grants): the fold starts at the owner,
  // whose rank comes from the community_id, and resolves outward to fixpoint.
  const rosterEids = new Set(
    editions.filter(e => e.vsk === VSK.ROLE || e.vsk === VSK.GRANT).map(e => e.eid),
  )
  runFold(rosterEids)

  // Phase 2 — everything else is judged against the settled CURRENT roster
  // (§5: a stale-but-once-valid citation grandfathers nothing).
  const otherEids = new Set(editions.map(e => e.eid).filter(eid => !rosterEids.has(eid)))
  runFold(otherEids, rosterFrom(ctx, accepted))

  return {
    entities: accepted,
    suspended,
    roster: rosterFrom(ctx, accepted),
    banlist: banlistFrom(accepted, ctx),
  }
}

// convenience coordinates
export const grantEid = (cid: Uint8Array, member: string) =>
  bytesToHex(grantLocator(cid, hexToBytes(member)))
export const banlistEid = (cid: Uint8Array) => bytesToHex(banlistLocator(cid))
export const registryEid = (cid: Uint8Array, creator: string) =>
  bytesToHex(inviteLinksLocator(cid, hexToBytes(creator)))
