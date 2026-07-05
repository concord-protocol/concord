/** Deterministic randomness for stress tests: reproducible failures only. */

/** mulberry32 — small, fast, deterministic PRNG. */
export function prng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export function shuffled<T>(items: readonly T[], rand: () => number): T[] {
  const out = [...items]
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1))
    ;[out[i], out[j]] = [out[j]!, out[i]!]
  }
  return out
}

export function pick<T>(items: readonly T[], rand: () => number): T {
  return items[Math.floor(rand() * items.length)]!
}

export function randomHex(rand: () => number, bytes = 32): string {
  let s = ''
  for (let i = 0; i < bytes * 2; i++) s += Math.floor(rand() * 16).toString(16)
  return s
}

export function randomBytesSeeded(rand: () => number, n = 32): Uint8Array {
  const b = new Uint8Array(n)
  for (let i = 0; i < n; i++) b[i] = Math.floor(rand() * 256)
  return b
}
