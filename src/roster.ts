/**
 * CORD-04 §2–§4 — the Roster: Roles, Grants, permission bits, position,
 * and the Banlist.
 */

// §3 — frozen permission bits. A retired bit is burned, never renumbered.
export const PERM = {
  MANAGE_ROLES: 1n << 0n,
  MANAGE_CHANNELS: 1n << 1n,
  MANAGE_METADATA: 1n << 2n,
  KICK: 1n << 3n,
  BAN: 1n << 4n,
  MANAGE_MESSAGES: 1n << 5n,
  CREATE_INVITE: 1n << 6n,
  RETIRED_MANAGE_INVITES: 1n << 7n, // retired — burned
  VIEW_AUDIT_LOG: 1n << 8n,
  MENTION_EVERYONE: 1n << 9n,
  RESERVED_MANAGE_EMOJI: 1n << 10n,
  RESERVED_PIN_MESSAGES: 1n << 11n,
  RESERVED_MANAGE_EVENTS: 1n << 12n,
} as const

export interface Role {
  role_id: string // hex32
  name: string // ≤ 64 bytes
  position: number // u32, lower is higher; owner is 0 (never a Role)
  permissions: string | number // decimal string on the wire; reader accepts either
  scope: { kind: 'server' } | { kind: 'channel'; channel_id: string }
  color?: number
}

export interface Grant {
  member: string // hex32 npub
  role_ids: string[] // empty = revoke
}

export const MAX_ROLES_PER_MEMBER = 64
export const MAX_ROLES_PER_COMMUNITY = 100
export const NAME_CAP_BYTES = 64 // protocol-wide (community, channel, role)

export function nameWithinCap(name: string): boolean {
  return new TextEncoder().encode(name).length <= NAME_CAP_BYTES
}

/** Reader accepts a number (older editions) or a string; always writes the string. */
export function parsePermissions(p: string | number): bigint {
  return typeof p === 'string' ? BigInt(p) : BigInt(p)
}
export function writePermissions(p: bigint): string {
  return p.toString(10) // decimal string — JS numbers corrupt past 2^53
}

/** Rank of a roleless member: effectively last. */
export const RANK_ROLELESS = Number.POSITIVE_INFINITY

export interface Roster {
  ownerPk: string
  roles: Map<string, Role> // by role_id
  grants: Map<string, Grant> // by member npub
}

/**
 * Community-wide cap: fold the 100 lowest role_ids, ignore the rest
 * (the same deterministic cap the member list uses).
 */
export function capRoles(roles: Map<string, Role>): Map<string, Role> {
  const ids = [...roles.keys()].sort()
  return new Map(ids.slice(0, MAX_ROLES_PER_COMMUNITY).map(id => [id, roles.get(id)!]))
}

/** A member's Roles, applying both caps deterministically. */
export function memberRoles(roster: Roster, npub: string): Role[] {
  const grant = roster.grants.get(npub)
  if (!grant) return []
  const capped = capRoles(roster.roles)
  const ids = [...grant.role_ids].sort().slice(0, MAX_ROLES_PER_MEMBER)
  return ids.map(id => capped.get(id)).filter((r): r is Role => r !== undefined)
}

/** Effective permissions: the union of the member's Roles' bits. Owner is supreme. */
export function effectivePermissions(roster: Roster, npub: string): bigint {
  if (npub === roster.ownerPk) return (1n << 64n) - 1n // supreme — every bit, incl. future ones
  return memberRoles(roster, npub).reduce((acc, r) => acc | parsePermissions(r.permissions), 0n)
}

/** Rank: owner is position 0; otherwise the lowest position among held Roles. */
export function rank(roster: Roster, npub: string): number {
  if (npub === roster.ownerPk) return 0
  const rs = memberRoles(roster, npub)
  if (rs.length === 0) return RANK_ROLELESS
  return Math.min(...rs.map(r => r.position))
}

/**
 * §5 — the one hard rule: the actor must hold the required bit AND strictly
 * outrank the target (equal cannot act on equal).
 */
export function authorize(
  roster: Roster,
  actor: string,
  bit: bigint,
  targetRank: number,
): boolean {
  if ((effectivePermissions(roster, actor) & bit) === 0n) return false
  return rank(roster, actor) < targetRank
}

// ---- §4 Banlist --------------------------------------------------------------

/** The whole list, replaced entire on every edit. */
export type Banlist = string[]

/**
 * Re-heal: after publishing, re-fold, and if your addition isn't in the head,
 * re-apply it atop the winner. Guarantees convergence to the union.
 */
export function rehealBanlist(head: Banlist, myAdditions: string[]): Banlist | null {
  const missing = myAdditions.filter(m => !head.includes(m))
  if (missing.length === 0) return null // nothing to heal
  return [...head, ...missing]
}
