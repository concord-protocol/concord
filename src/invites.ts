/**
 * CORD-05 — Invites: the bundle, the link fragment (with relay dictionary),
 * the kind 33301 addressable event, the Invite List, and the Registry.
 */
import { v2 as nip44 } from 'nostr-tools/nip44'
import { bytesEqual, bytesToHex, hexToBytes, utf8 } from './bytes.js'
import { communityId, inviteBundleId, inviteBundleKey, inviteBundleSigner } from './derive.js'
import { signEvent, verifyEvent, type SignedEvent } from './events.js'

export const KIND_INVITE_BUNDLE = 33301
export const KIND_INVITE_LIST = 13303
export const VSK_LIVE = '6'
export const VSK_TOMBSTONE = '9'

export const MAX_CHANNELS_IN_BUNDLE = 256 // Vector's ceiling — bound before allocating
export const MAX_RELAYS = 5 // the Community's cap (CORD-02 §6)
export const MAX_FRAGMENT_RELAYS = 3 // bootstrap only — the bundle carries the real set

export interface InviteBundle {
  community_id: string
  owner: string
  owner_salt: string
  community_root: string
  root_epoch: number
  channels: { id: string; key: string; epoch: number; name: string }[]
  relays: string[]
  name: string
  icon?: unknown
  expires_at?: number // unix ms: past it, preview renders, joining refuses
  creator_npub?: string
  label?: string
}

/** Owner proof: the bundle can't smuggle a false owner — refused on mismatch. */
export function verifyBundleOwner(b: InviteBundle): boolean {
  return bytesEqual(
    communityId(hexToBytes(b.owner), hexToBytes(b.owner_salt)),
    hexToBytes(b.community_id),
  )
}

/** A bundle is attacker-crafted input: bound before allocating. */
export function boundBundle(b: InviteBundle): InviteBundle {
  if (b.channels.length > MAX_CHANNELS_IN_BUNDLE)
    throw new Error('bundle exceeds sane channel count')
  return { ...b, relays: b.relays.slice(0, MAX_RELAYS) }
}

export function joiningAllowed(b: InviteBundle, nowMs: number): boolean {
  return b.expires_at === undefined || nowMs <= b.expires_at
}

// ---- §2 the 33301 addressable event ----------------------------------------

export function publishBundle(token: Uint8Array, bundle: InviteBundle, created_at: number): SignedEvent {
  const signer = inviteBundleSigner(token)
  return signEvent(
    {
      kind: KIND_INVITE_BUNDLE,
      pubkey: signer.pk,
      content: nip44.encrypt(JSON.stringify(bundle), inviteBundleKey(token)),
      tags: [
        ['d', bytesToHex(inviteBundleId(token))],
        ['vsk', VSK_LIVE],
      ],
      created_at,
    },
    signer.sk,
  )
}

/** Revocation tombstone: token-signed, replacing the bundle at the coordinate. */
export function publishTombstone(token: Uint8Array, created_at: number): SignedEvent {
  const signer = inviteBundleSigner(token)
  return signEvent(
    {
      kind: KIND_INVITE_BUNDLE,
      pubkey: signer.pk,
      content: '',
      tags: [
        ['d', bytesToHex(inviteBundleId(token))],
        ['vsk', VSK_TOMBSTONE],
      ],
      created_at,
    },
    signer.sk,
  )
}

export type FetchResult =
  | { status: 'live'; bundle: InviteBundle }
  | { status: 'revoked' }
  | { status: 'none' }

/**
 * Fetch: reject any event at the coordinate not signed by the token's signer
 * (squatting is useless), then read the newest surviving event.
 */
export function fetchBundle(events: SignedEvent[], token: Uint8Array): FetchResult {
  const signer = inviteBundleSigner(token)
  const d = bytesToHex(inviteBundleId(token))
  const candidates = events
    .filter(e => e.kind === KIND_INVITE_BUNDLE)
    .filter(e => e.tags.some(t => t[0] === 'd' && t[1] === d))
    .filter(e => e.pubkey === signer.pk && verifyEvent(e)) // impostors dropped unread
    .sort((a, b) => b.created_at - a.created_at)
  const head = candidates[0]
  if (!head) return { status: 'none' }
  const vsk = head.tags.find(t => t[0] === 'vsk')?.[1]
  if (vsk === VSK_TOMBSTONE) return { status: 'revoked' }
  const plaintext = nip44.decrypt(head.content, inviteBundleKey(token))
  return { status: 'live', bundle: JSON.parse(plaintext) as InviteBundle }
}

// ---- §3 the link fragment + relay dictionary --------------------------------

export const FRAGMENT_VERSION = 3

/** The stock set: four primaries, selected by one flag. */
export const RELAY_DICTIONARY: Record<number, string> = {
  1: 'wss://jskitty.com/nostr', // Vector
  2: 'wss://asia.vectorapp.io/nostr', // Vector
  3: 'wss://relay.ditto.pub', // Soapbox
  4: 'wss://relay.dreamith.to', // Soapbox
}
export const STOCK_RELAYS = [1, 2, 3, 4].map(i => RELAY_DICTIONARY[i]!)

const FLAG_STOCK_SET = 0x01

function b64urlEncode(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url') // base64url, no padding
}
function b64urlDecode(s: string): Uint8Array {
  if (s.includes('=')) throw new Error('fragment must be unpadded')
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

/** Encode `[version][flags][relays?][token:32]`. */
export function encodeFragment(token: Uint8Array, relays: string[] | 'stock'): string {
  if (token.length !== 32) throw new Error('token must be 32 bytes')
  const parts: number[] = [FRAGMENT_VERSION]
  if (relays === 'stock') {
    parts.push(FLAG_STOCK_SET) // zero additional relay bytes
  } else {
    if (relays.length > MAX_FRAGMENT_RELAYS)
      throw new Error(`fragment carries at most ${MAX_FRAGMENT_RELAYS} bootstrap relays`)
    parts.push(0x00, relays.length)
    for (const r of relays) {
      const dictId = Object.entries(RELAY_DICTIONARY).find(([, url]) => url === r)?.[0]
      if (dictId) {
        parts.push(Number(dictId)) // one byte, no literal
      } else if (r.startsWith('wss://')) {
        const host = utf8(r.slice('wss://'.length))
        parts.push(0, host.length, ...host) // wss-implied literal
      } else {
        const full = utf8(r)
        parts.push(255, full.length, ...full) // verbatim literal
      }
    }
  }
  return b64urlEncode(new Uint8Array([...parts, ...token]))
}

export interface DecodedFragment {
  version: number
  relays: string[]
  token: Uint8Array
}

export function decodeFragment(fragment: string): DecodedFragment {
  const b = b64urlDecode(fragment)
  let i = 0
  const version = b[i++]!
  if (version < FRAGMENT_VERSION)
    throw new Error('legacy link: refusing to decode against the wrong dictionary')
  const flags = b[i++]!
  const relays: string[] = []
  if (flags & FLAG_STOCK_SET) {
    relays.push(...STOCK_RELAYS)
  } else {
    const count = b[i++]!
    if (count > MAX_FRAGMENT_RELAYS) throw new Error('too many bootstrap relays')
    for (let k = 0; k < count; k++) {
      const lead = b[i++]!
      if (lead >= 1 && lead <= 254) {
        const url = RELAY_DICTIONARY[lead]
        if (!url) throw new Error(`unknown dictionary id ${lead}`)
        relays.push(url)
      } else {
        const len = b[i++]!
        const bytes = b.slice(i, i + len)
        i += len
        relays.push(
          lead === 0
            ? 'wss://' + new TextDecoder().decode(bytes) // wss re-prepended
            : new TextDecoder().decode(bytes), // verbatim
        )
      }
    }
  }
  const token = b.slice(i)
  if (token.length !== 32) throw new Error('malformed fragment: token must be 32 bytes')
  return { version, relays, token }
}

// ---- §4 the Invite List ------------------------------------------------------

export interface InviteEntry {
  token: string // the link's secret AND its merge key
  community_id: string
  url: string
  label?: string
  created_at: number
  expires_at?: number
  [k: string]: unknown
}
export interface InviteTombstone {
  token: string
  community_id: string
}
export interface InviteList {
  entries: InviteEntry[]
  tombstones: InviteTombstone[]
}

/** Entries immutable, tombstones union, a tombstone terminally beats an entry. */
export function mergeInviteLists(a: InviteList, b: InviteList): InviteList {
  const tombs = new Map<string, InviteTombstone>()
  for (const t of [...a.tombstones, ...b.tombstones]) tombs.set(t.token, t)
  const entries = new Map<string, InviteEntry>()
  for (const e of [...a.entries, ...b.entries]) {
    if (tombs.has(e.token)) continue // stale device can never resurrect a revoked link
    if (!entries.has(e.token)) entries.set(e.token, e) // immutable once minted
  }
  return { entries: [...entries.values()], tombstones: [...tombs.values()] }
}

// ---- §5 the Registry ---------------------------------------------------------

/**
 * Fold every creator's Registry (locators only) into one aggregate active-set,
 * honoring a Registry only while its author holds CREATE_INVITE.
 */
export function foldRegistries(
  registries: { creator: string; locators: string[] }[],
  hasCreateInvite: (npub: string) => boolean,
): Set<string> {
  const active = new Set<string>()
  for (const r of registries) {
    if (!hasCreateInvite(r.creator)) continue
    for (const loc of r.locators) active.add(loc)
  }
  return active
}

/** Non-empty means Public; empty means Private. */
export function isPublicCommunity(activeSet: Set<string>): boolean {
  return activeSet.size > 0
}
