/**
 * Nostr event plumbing for the model: rumors (unsigned), signed events,
 * ids per NIP-01, and Concord millisecond time (CORD-02 §4).
 */
import { schnorr } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, utf8 } from './bytes.js'

export type Tag = string[]

export interface Rumor {
  id: string
  kind: number
  pubkey: string
  content: string
  tags: Tag[]
  created_at: number
  // rumors are unsigned — no sig
}

export interface SignedEvent extends Rumor {
  sig: string
}

/** NIP-01 canonical serialization → sha256 → event id. */
export function eventId(e: Omit<Rumor, 'id'>): string {
  const ser = JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])
  return bytesToHex(sha256(utf8(ser)))
}

export function makeRumor(e: Omit<Rumor, 'id'>): Rumor {
  return { ...e, id: eventId(e) }
}

export function signEvent(e: Omit<Rumor, 'id'>, sk: Uint8Array): SignedEvent {
  const id = eventId(e)
  const sig = bytesToHex(schnorr.sign(id, sk))
  return { ...e, id, sig }
}

export function verifyEvent(e: SignedEvent): boolean {
  if (e.id !== eventId(e)) return false
  try {
    return schnorr.verify(e.sig, e.id, e.pubkey)
  } catch {
    return false
  }
}

export function pubkeyOf(sk: Uint8Array): string {
  return bytesToHex(schnorr.getPublicKey(sk))
}

export function tagValue(e: { tags: Tag[] }, name: string): string | undefined {
  return e.tags.find(t => t[0] === name)?.[1]
}

export function tag(e: { tags: Tag[] }, name: string): Tag | undefined {
  return e.tags.find(t => t[0] === name)
}

/**
 * CORD-02 §4 — millisecond ordering: a rumor carries ["ms", 0..999] and the
 * true time is created_at * 1000 + ms. Every protocol comparison uses this.
 */
export function msTime(e: { created_at: number; tags: Tag[] }): number {
  const ms = Number(tagValue(e, 'ms') ?? '0')
  return e.created_at * 1000 + ms
}

/**
 * The ms tag is `<0..999>`: anything else is malformed (it would smuggle
 * extra "future" past the clock check or grind the millisecond ordering),
 * and a fold drops the entry rather than interpret it.
 */
export function hasValidMs(e: { tags: Tag[] }): boolean {
  const raw = tagValue(e, 'ms')
  if (raw === undefined) return true // absent means 0
  if (!/^\d{1,3}$/.test(raw)) return false
  const n = Number(raw)
  return Number.isInteger(n) && n >= 0 && n <= 999
}
