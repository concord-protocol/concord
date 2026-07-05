/**
 * CORD-01 — Private Streams.
 *
 * A stream event is a kind 1059 wrap signed by the SHARED stream key,
 * NIP-44-encrypted under the stream conversation key (self-ECDH), carrying a
 * seal (kind 20013 encrypted / 20014 plaintext) signed by the author's real
 * key, carrying the unsigned rumor.
 *
 * Inversions vs NIP-59: fixed author + ephemeral "p" tag; wrap encrypted to
 * the stream conv key (never the p-tagged key); seal kinds 20013/20014 (not
 * 13); created_at is NOT tweaked.
 */
import { v2 as nip44 } from 'nostr-tools/nip44'
import { schnorr } from '@noble/curves/secp256k1'
import { bytesToHex, randomBytes } from './bytes.js'
import type { GroupKey } from './derive.js'
import { makeRumor, signEvent, verifyEvent, type Rumor, type SignedEvent } from './events.js'

export const KIND_WRAP = 1059
export const KIND_WRAP_EPHEMERAL = 21059 // relays MUST NOT store
export const KIND_SEAL_ENCRYPTED = 20013
export const KIND_SEAL_PLAINTEXT = 20014

export type SealForm = 'encrypted' | 'plaintext'

/** NIP-44 v2 hard-caps plaintext at 65,535 bytes; the library is lenient, the
 * protocol is not. Every encryption layer in Concord rides this limit. */
export const NIP44_MAX = 65535
function nip44EncryptStrict(plaintext: string, convKey: Uint8Array): string {
  const bytes = new TextEncoder().encode(plaintext).length
  if (bytes > NIP44_MAX)
    throw new StreamError(`plaintext exceeds the NIP-44 cap: ${bytes} > ${NIP44_MAX}`)
  return nip44.encrypt(plaintext, convKey)
}

/** Build the seal: the author's real signature over the rumor (or its ciphertext). */
export function makeSeal(
  rumor: Rumor,
  authorSk: Uint8Array,
  form: SealForm,
  convKey: Uint8Array,
): SignedEvent {
  const content =
    form === 'encrypted'
      ? nip44EncryptStrict(JSON.stringify(rumor), convKey)
      : JSON.stringify(rumor) // the rumor verbatim — exact wire bytes
  return signEvent(
    {
      kind: form === 'encrypted' ? KIND_SEAL_ENCRYPTED : KIND_SEAL_PLAINTEXT,
      pubkey: bytesToHex(schnorr.getPublicKey(authorSk)),
      content,
      tags: [],
      created_at: rumor.created_at,
    },
    authorSk,
  )
}

/** Wrap a seal at the stream address: fixed author = stream pk, ephemeral "p". */
export function wrapSeal(
  seal: SignedEvent,
  stream: GroupKey,
  opts: { ephemeral?: boolean; ephemeralPubkey?: string } = {},
): SignedEvent {
  const p = opts.ephemeralPubkey ?? bytesToHex(schnorr.getPublicKey(randomBytes(32)))
  return signEvent(
    {
      kind: opts.ephemeral ? KIND_WRAP_EPHEMERAL : KIND_WRAP,
      pubkey: stream.pk,
      content: nip44EncryptStrict(JSON.stringify(seal), stream.convKey),
      tags: [['p', p]],
      created_at: seal.created_at, // created_at should not be altered or tweaked
    },
    stream.sk,
  )
}

/** One-shot: rumor → seal → wrap. */
export function wrapRumor(
  rumorFields: Omit<Rumor, 'id'>,
  authorSk: Uint8Array,
  stream: GroupKey,
  form: SealForm,
  opts: { ephemeral?: boolean } = {},
): { rumor: Rumor; seal: SignedEvent; wrap: SignedEvent } {
  const rumor = makeRumor(rumorFields)
  const seal = makeSeal(rumor, authorSk, form, stream.convKey)
  const wrap = wrapSeal(seal, stream, opts)
  return { rumor, seal, wrap }
}

export class StreamError extends Error {}

/**
 * Open a wrap with the stream key. Verifies the wrap signature is the
 * stream's, the seal signature is the author's, and that the seal's KIND
 * declares its form (a reader never sniffs the content).
 */
export function unwrapEvent(
  wrap: SignedEvent,
  stream: GroupKey,
): { rumor: Rumor; seal: SignedEvent; form: SealForm } {
  if (wrap.kind !== KIND_WRAP && wrap.kind !== KIND_WRAP_EPHEMERAL)
    throw new StreamError('not a wrap')
  if (wrap.pubkey !== stream.pk) throw new StreamError('wrap is not at this stream address')
  if (!verifyEvent(wrap)) throw new StreamError('bad stream signature')

  let sealJson: string
  try {
    sealJson = nip44.decrypt(wrap.content, stream.convKey)
  } catch {
    throw new StreamError('wrap does not decrypt under this stream key')
  }
  let seal: SignedEvent
  try {
    seal = JSON.parse(sealJson) as SignedEvent
  } catch {
    throw new StreamError('wrap payload is not a seal')
  }
  if (!seal || typeof seal !== 'object' || !verifyEvent(seal))
    throw new StreamError('bad seal signature')

  let form: SealForm
  let rumorJson: string
  if (seal.kind === KIND_SEAL_ENCRYPTED) {
    form = 'encrypted'
    try {
      rumorJson = nip44.decrypt(seal.content, stream.convKey)
    } catch {
      throw new StreamError('encrypted seal does not decrypt under this stream key')
    }
  } else if (seal.kind === KIND_SEAL_PLAINTEXT) {
    form = 'plaintext'
    rumorJson = seal.content
  } else {
    throw new StreamError(`unexpected seal kind ${seal.kind}`)
  }

  let rumor: Rumor
  try {
    rumor = JSON.parse(rumorJson) as Rumor
  } catch {
    throw new StreamError('seal payload is not a rumor')
  }
  if (!rumor || typeof rumor !== 'object' || rumor.pubkey !== seal.pubkey)
    throw new StreamError('rumor author does not match seal author')
  return { rumor, seal, form }
}

/**
 * CORD-01 Binding / CORD-03 §3 — strict-equal check of the committed
 * ["channel", id] and ["epoch", n] tags against the coordinate whose key
 * opened the wrap. Receivers MUST drop a mismatch.
 */
export function checkBinding(
  rumor: Rumor,
  expected: { channelId: string; epoch: number | bigint },
): boolean {
  const ch = rumor.tags.find(t => t[0] === 'channel')?.[1]
  const ep = rumor.tags.find(t => t[0] === 'epoch')?.[1]
  return ch === expected.channelId && ep === String(expected.epoch)
}
