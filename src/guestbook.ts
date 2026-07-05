/**
 * CORD-02 §5 — the Guestbook Plane: Joins, Leaves, Kicks, Snapshots, and the
 * coalescing fold that yields the Complete Memberlist.
 */
import { hasValidMs, msTime, tag, tagValue, type Rumor } from './events.js'

export const KIND_JOIN_LEAVE = 3306
export const KIND_KICK = 3309
export const KIND_SNAPSHOT = 3312

export const SNAPSHOT_CHUNK = 400 // members per snapshot event
export const MAX_FUTURE_MS = 60 * 60 * 1000 // one hour ahead → dropped outright

export type MemberStatus = 'present' | 'departed'

export interface MemberState {
  status: MemberStatus
  timeMs: number
  rumorId: string
  /** 'self' (Join/Leave), 'kick', or 'snapshot' (secondhand seed) */
  source: 'self' | 'kick' | 'snapshot'
}

export interface GuestbookContext {
  nowMs: number
  /** honored only if its signer holds KICK and outranks the target (CORD-04) */
  kickAuthorized: (kick: Rumor, target: string) => boolean
  /** snapshots honored only from the npub whose Refounding minted the epoch */
  refounder?: string
  /** authors observed publishing anywhere in the Community (forward-only) */
  observed?: { pubkey: string; timeMs: number }[]
  banlist?: Set<string>
}

/** Does candidate supersede incumbent? Latest wins; ties break on the LOWER rumor id. */
function supersedes(cand: { timeMs: number; rumorId: string }, inc?: MemberState): boolean {
  if (!inc) return true
  if (cand.timeMs !== inc.timeMs) return cand.timeMs > inc.timeMs
  return cand.rumorId < inc.rumorId
}

export interface GuestbookFold {
  /** one final state per npub */
  states: Map<string, MemberState>
  /** coalesced ∪ observed − banlist */
  members: Set<string>
}

export function foldGuestbook(rumors: Rumor[], ctx: GuestbookContext): GuestbookFold {
  const states = new Map<string, MemberState>()

  const consider = (
    npub: string,
    cand: MemberState,
  ) => {
    const inc = states.get(npub)
    // a snapshot merely SEEDS: any self-signed entry or authorized Kick newer
    // than it supersedes it — and at equal time the firsthand word wins too.
    if (inc && cand.source === 'snapshot' && inc.source !== 'snapshot') {
      if (cand.timeMs <= inc.timeMs) return
    }
    if (inc && inc.source === 'snapshot' && cand.source !== 'snapshot') {
      if (cand.timeMs >= inc.timeMs) {
        states.set(npub, cand)
      }
      return
    }
    if (supersedes(cand, inc)) states.set(npub, cand)
  }

  for (const r of rumors) {
    // a malformed ms tag (outside 0..999) is dropped, not interpreted
    if (!hasValidMs(r)) continue
    const t = msTime(r)
    // an entry dated more than one hour ahead of the receiver's clock is dropped outright
    if (t > ctx.nowMs + MAX_FUTURE_MS) continue

    if (r.kind === KIND_JOIN_LEAVE) {
      const verb = r.content
      if (verb !== 'join' && verb !== 'leave') continue
      consider(r.pubkey, {
        status: verb === 'join' ? 'present' : 'departed',
        timeMs: t,
        rumorId: r.id,
        source: 'self',
      })
    } else if (r.kind === KIND_KICK) {
      const target = tagValue(r, 'p')
      if (!target) continue
      if (!ctx.kickAuthorized(r, target)) continue // dropped unless KICK + outrank
      consider(target, { status: 'departed', timeMs: t, rumorId: r.id, source: 'kick' })
    } else if (r.kind === KIND_SNAPSHOT) {
      if (ctx.refounder === undefined || r.pubkey !== ctx.refounder) continue // refounder-only
      const snap = tag(r, 'snap')
      if (!snap) continue
      let listed: string[]
      try {
        listed = JSON.parse(r.content)
      } catch {
        continue
      }
      // present members only; absence just means "no seed", never a negative state
      for (const npub of listed) {
        consider(npub, { status: 'present', timeMs: t, rumorId: r.id, source: 'snapshot' })
      }
    }
  }

  // merge observed authors: forward-only — activity newer than the latest
  // Leave/Kick re-enters; old history never resurrects a departed member.
  for (const obs of ctx.observed ?? []) {
    if (obs.timeMs > ctx.nowMs + MAX_FUTURE_MS) continue
    const inc = states.get(obs.pubkey)
    if (!inc) {
      states.set(obs.pubkey, {
        status: 'present',
        timeMs: obs.timeMs,
        rumorId: '',
        source: 'self',
      })
    } else if (inc.status === 'departed' && obs.timeMs > inc.timeMs) {
      states.set(obs.pubkey, {
        status: 'present',
        timeMs: obs.timeMs,
        rumorId: '',
        source: 'self',
      })
    }
  }

  const members = new Set<string>()
  for (const [npub, st] of states) {
    if (st.status === 'present' && !ctx.banlist?.has(npub)) members.add(npub)
  }
  return { states, members }
}

/**
 * §5 Snapshots — the refounder coalesces the old epoch, subtracts the removed,
 * and publishes present members chunked at 400 per event, all chunks sharing
 * one snapshot id and one timestamp.
 */
export function buildSnapshotRumors(
  members: string[],
  snapshotId: string,
  created_at: number,
  ms: number,
): Omit<Rumor, 'id' | 'pubkey'>[] {
  const n = Math.max(1, Math.ceil(members.length / SNAPSHOT_CHUNK))
  const out: Omit<Rumor, 'id' | 'pubkey'>[] = []
  for (let i = 0; i < n; i++) {
    const chunk = members.slice(i * SNAPSHOT_CHUNK, (i + 1) * SNAPSHOT_CHUNK)
    out.push({
      kind: KIND_SNAPSHOT,
      content: JSON.stringify(chunk),
      tags: [
        ['ms', String(ms)],
        ['snap', snapshotId, String(i + 1), String(n)],
      ],
      created_at,
    })
  }
  return out
}
