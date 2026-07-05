/** Byte helpers shared by the Concord reference model. */
import { bytesToHex as b2h, hexToBytes as h2b } from '@noble/hashes/utils'
import { randomBytes as nobleRandom } from '@noble/hashes/utils'

export const bytesToHex = b2h
export const hexToBytes = h2b
export const randomBytes = (n = 32): Uint8Array => nobleRandom(n)

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** u64 big-endian encoding (epoch_be, len64, version_be). */
export function u64be(n: number | bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false)
  return b
}

export const ZERO32 = new Uint8Array(32)

/** Lexicographic comparison of byte strings (used for canonical tie-breaks). */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const x = a[i]! - b[i]!
    if (x !== 0) return x < 0 ? -1 : 1
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return compareBytes(a, b) === 0
}
