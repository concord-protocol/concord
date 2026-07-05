/**
 * CORD-02 §8 — the Community List (kind 13302): a member's self-encrypted,
 * replaceable sync document, merged across devices without coordination.
 */

export const KIND_COMMUNITY_LIST = 13302
export const MAX_MEMBERSHIPS = 50 // protocol constant, not client taste
export const NIP44_MAX_PLAINTEXT = 65535 // NIP-44 plaintext hard cap, bytes

/** Join material: the bundle's membership subset — never icon, never link fields. */
export interface JoinMaterial {
  community_id: string
  owner: string
  owner_salt: string
  community_root: string
  root_epoch: number
  channels: { id: string; key: string; epoch: number; name: string }[]
  relays: string[]
  name: string
  [k: string]: unknown // round-trip discipline: preserve what you don't understand
}

export interface CommunityEntry {
  community_id: string
  seed: JoinMaterial // earliest epoch held — only ever moves BACKward on merge
  current: JoinMaterial // freshest — replaced on every Refounding or rename
  added_at: number // ms; tiebreaks against a tombstone
  [k: string]: unknown
}

export interface Tombstone {
  community_id: string
  removed_at: number // ms
}

export interface CommunityList {
  entries: CommunityEntry[]
  tombstones: Tombstone[]
}

/** Canonical bytes of a snapshot: JSON with lexicographically sorted keys. */
export function canonicalBytes(v: unknown): Uint8Array {
  const canon = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(canon)
    if (x && typeof x === 'object') {
      const o: Record<string, unknown> = {}
      for (const k of Object.keys(x as Record<string, unknown>).sort())
        o[k] = canon((x as Record<string, unknown>)[k])
      return o
    }
    return x
  }
  return new TextEncoder().encode(JSON.stringify(canon(v)))
}

function lexLower(a: JoinMaterial, b: JoinMaterial): JoinMaterial {
  const ab = canonicalBytes(a)
  const bb = canonicalBytes(b)
  for (let i = 0; i < Math.min(ab.length, bb.length); i++) {
    if (ab[i]! !== bb[i]!) return ab[i]! < bb[i]! ? a : b
  }
  return ab.length <= bb.length ? a : b
}

/** seed keeps the LOWER epoch (widest reach); current keeps the HIGHER (freshest);
 * an epoch tie breaks on the lexicographically lowest canonical bytes — a total order. */
export function mergeEntry(a: CommunityEntry, b: CommunityEntry): CommunityEntry {
  const seed =
    a.seed.root_epoch !== b.seed.root_epoch
      ? a.seed.root_epoch < b.seed.root_epoch
        ? a.seed
        : b.seed
      : lexLower(a.seed, b.seed)
  const current =
    a.current.root_epoch !== b.current.root_epoch
      ? a.current.root_epoch > b.current.root_epoch
        ? a.current
        : b.current
      : lexLower(a.current, b.current)
  return {
    ...a,
    ...b, // round-trip unknown fields from both; later spread only affects overlaps
    community_id: a.community_id,
    seed,
    current,
    added_at: Math.max(a.added_at, b.added_at),
  }
}

/** Merge two device copies. Tombstones are permanent; the newest of added_at
 * and removed_at wins, so a re-join resurrects while a backfill can't re-add.
 *
 * NOTE (a stress-test finding): entries are NOT discarded when tombstoned.
 * §8's document holds "every Community they're in and every one they've
 * left" — a left Community's entry persists, and liveness is *derived* from
 * the tombstone. Discarding suppressed entries at merge time makes the merge
 * non-associative (device convergence would depend on gossip order), which
 * would contradict "merges without coordination".
 */
export function mergeLists(a: CommunityList, b: CommunityList): CommunityList {
  const tombs = new Map<string, Tombstone>()
  for (const t of [...a.tombstones, ...b.tombstones]) {
    const prev = tombs.get(t.community_id)
    if (!prev || t.removed_at > prev.removed_at) tombs.set(t.community_id, t)
  }

  const entries = new Map<string, CommunityEntry>()
  for (const e of [...a.entries, ...b.entries]) {
    const prev = entries.get(e.community_id)
    entries.set(e.community_id, prev ? mergeEntry(prev, e) : e)
  }

  const merged: CommunityList = {
    entries: [...entries.values()],
    tombstones: [...tombs.values()], // tombstones never pruned
  }

  if (liveEntries(merged).length > MAX_MEMBERSHIPS)
    throw new Error(`Community List caps at ${MAX_MEMBERSHIPS} memberships`)

  return merged
}

/** The memberships currently alive: the newest of added_at and removed_at
 * wins per community; a tie does not resurrect. */
export function liveEntries(list: CommunityList): CommunityEntry[] {
  const tombs = new Map(list.tombstones.map(t => [t.community_id, t]))
  return list.entries.filter(e => {
    const t = tombs.get(e.community_id)
    return !t || e.added_at > t.removed_at
  })
}

/** The list must fit one NIP-44 event. */
export function fitsNip44(list: CommunityList): boolean {
  return canonicalBytes(list).length <= NIP44_MAX_PLAINTEXT
}
