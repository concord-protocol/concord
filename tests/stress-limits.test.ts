/**
 * Stress: physical limits. Every Concord event must survive NIP-44's 65,535-
 * byte plaintext hard cap at EVERY encryption layer (rumor → seal → wrap).
 * The spec's constants (120 recipients, 400 snapshot members, 50 memberships)
 * implicitly promise this; these tests verify the arithmetic — and record,
 * as canon, the two places where the spec's own words are in tension with it.
 */
import { describe, expect, it } from 'vitest'
import { bytesToHex, hexToBytes, randomBytes, utf8 } from '../src/bytes.js'
import { communityId, groupKey } from '../src/derive.js'
import { makeRumor, pubkeyOf, type Rumor } from '../src/events.js'
import { buildSnapshotRumors, SNAPSHOT_CHUNK } from '../src/guestbook.js'
import {
  canonicalBytes,
  fitsNip44,
  MAX_MEMBERSHIPS,
  NIP44_MAX_PLAINTEXT,
  type CommunityEntry,
  type CommunityList,
  type JoinMaterial,
} from '../src/communityList.js'
import { encodeFragment, MAX_CHANNELS_IN_BUNDLE } from '../src/invites.js'
import { buildRotation, RECIPIENTS_PER_EVENT } from '../src/rekey.js'
import { unwrapEvent, wrapRumor } from '../src/stream.js'

const NIP44_CAP = 65535

/** The real test: the FULL envelope round-trips, meaning every nip44 layer fit. */
function envelopeFits(rumor: Rumor, authorSk: Uint8Array): number {
  const stream = groupKey('concord/test-stream', randomBytes(32))
  const { seal, wrap } = wrapRumor(rumor, authorSk, stream, 'encrypted')
  // both plaintexts must be under the cap — nip44 would have thrown otherwise,
  // but assert explicitly so the numbers are on the record
  expect(utf8(JSON.stringify(rumor)).length).toBeLessThanOrEqual(NIP44_CAP)
  expect(utf8(JSON.stringify(seal)).length).toBeLessThanOrEqual(NIP44_CAP)
  expect(unwrapEvent(wrap, stream).rumor.id).toBe(rumor.id)
  return utf8(JSON.stringify(seal)).length
}

describe('limits — the rekey blob budget (CORD-06 §1)', () => {
  const rotatorSk = randomBytes(32)

  it('a full 120-recipient chunk survives the double-wrap: NIP-44 fits at every layer', () => {
    const recipients = Array.from({ length: RECIPIENTS_PER_EVENT }, () => pubkeyOf(randomBytes(32)))
    const [chunk] = buildRotation({
      rotatorSk, recipients,
      scopeId: randomBytes(32), newEpoch: 3, prevEpoch: 2,
      prevKey: randomBytes(32), newKey: randomBytes(32),
    })
    const sealBytes = envelopeFits(chunk!, rotatorSk)
    // measured: ≈55,050 bytes at the seal layer — it fits, but with only ~16%
    // headroom. 120 is close to the ceiling, not a round number with slack.
    expect(sealBytes).toBeLessThan(NIP44_CAP)
    expect(sealBytes).toBeGreaterThan(NIP44_CAP * 0.75)
  })

  it('the 120 cap is load-bearing: ~240 recipients in one event would blow the wrap layer', () => {
    // build a double-size chunk manually to show WHY the constant exists
    const recipients = Array.from({ length: 240 }, () => pubkeyOf(randomBytes(32)))
    const rumors = buildRotation({
      rotatorSk, recipients,
      scopeId: randomBytes(32), newEpoch: 3, prevEpoch: 2,
      prevKey: randomBytes(32), newKey: randomBytes(32),
    })
    expect(rumors.length).toBe(2) // the model chunks — merged, the seal layer would exceed:
    const mergedContent = JSON.stringify([
      ...JSON.parse(rumors[0]!.content),
      ...JSON.parse(rumors[1]!.content),
    ])
    const merged = makeRumor({ ...rumors[0]!, content: mergedContent })
    // rumor alone is ~53KB; nip44 of it inside the seal (~71KB) exceeds the wrap's plaintext cap
    const rumorBytes = utf8(JSON.stringify(merged)).length
    expect(rumorBytes * (4 / 3)).toBeGreaterThan(NIP44_CAP)
  })
})

describe('limits — the snapshot budget (CORD-02 §5)', () => {
  it('a full 400-member snapshot chunk survives the double-wrap', () => {
    const members = Array.from({ length: SNAPSHOT_CHUNK }, () => pubkeyOf(randomBytes(32)))
    const refounderSk = randomBytes(32)
    const [chunk] = buildSnapshotRumors(members, 'snap', 1722500000, 0)
    const rumor = makeRumor({ ...chunk!, pubkey: pubkeyOf(refounderSk) })
    const sealBytes = envelopeFits(rumor, refounderSk)
    expect(sealBytes).toBeLessThan(NIP44_CAP * 0.8) // ample headroom
  })
})

describe('limits — the banlist ceiling (CORD-04 §4)', () => {
  it('the banlist ceiling: an edition must fit the double-wrap, landing the practical ceiling near 500 bans (as §4 now documents)', () => {
    // 04.md §4: "unbounded by rule but not by physics … the practical ceiling
    // near 500 npubs". NIP-44's padding rounds up aggressively, so the real
    // ceiling sits far below naive per-entry arithmetic. Measured:
    const ownerSk = randomBytes(32)
    const ban = (n: number) =>
      makeRumor({
        kind: 3308,
        pubkey: pubkeyOf(ownerSk),
        content: JSON.stringify(Array.from({ length: n }, () => bytesToHex(randomBytes(32)))),
        tags: [['vsk', '4'], ['eid', 'ee'.repeat(32)], ['ev', '1']],
        created_at: 1,
      })
    // measured boundary: 450 bans round-trips…
    expect(() => envelopeFits(ban(450), ownerSk)).not.toThrow()
    // …600 bans already exceeds the wrap layer (seal JSON ≈65,965 > 65,535)
    const stream = groupKey('concord/test-stream', randomBytes(32))
    expect(() => wrapRumor(ban(600), ownerSk, stream, 'encrypted')).toThrow()
    // §4's rule: a client refuses an edit that would not fit rather than
    // publishing one strict readers drop — which is exactly what the model does.
  })
})

describe('limits — the Community List budget (CORD-02 §8)', () => {
  const mkMaterial = (channels: number): JoinMaterial => ({
    community_id: bytesToHex(randomBytes(32)),
    owner: bytesToHex(randomBytes(32)),
    owner_salt: bytesToHex(randomBytes(32)),
    community_root: bytesToHex(randomBytes(32)),
    root_epoch: 3,
    channels: Array.from({ length: channels }, (_, i) => ({
      id: bytesToHex(randomBytes(32)), key: bytesToHex(randomBytes(32)), epoch: 2, name: `channel-${i}`,
    })),
    relays: ['wss://jskitty.com/nostr', 'wss://asia.vectorapp.io/nostr', 'wss://relay.ditto.pub'],
    name: 'A Community With A Typical Name',
  })
  const mkEntry = (channels: number): CommunityEntry => {
    const m = mkMaterial(channels)
    return { community_id: m.community_id, seed: m, current: { ...m }, added_at: 1_719_800_000_000 }
  }
  const listOf = (n: number, channels: number): CommunityList => ({
    entries: Array.from({ length: n }, () => mkEntry(channels)),
    tombstones: [],
  })

  it('the spec’s claim holds for lean memberships: 50 public-channel-only communities fit one NIP-44 event', () => {
    expect(MAX_MEMBERSHIPS).toBe(50)
    expect(NIP44_MAX_PLAINTEXT).toBe(65535)
    expect(fitsNip44(listOf(50, 0))).toBe(true)
  })

  it('the 50-membership cap is not the whole budget (as §8 now documents): ONE private channel per membership already blows the byte cap', () => {
    // §8: "the membership cap bounds the common case, the byte cap is the law"
    // — because join material carries every granted private channel's
    // (id, key, epoch, name), duplicated in seed AND current. Measured:
    //   50 memberships, 0 private channels each: 54,329 bytes  (fits, 17% headroom)
    //   50 memberships, 1 private channel each:  71,829 bytes  (over the cap)
    expect(fitsNip44(listOf(50, 0))).toBe(true)
    expect(fitsNip44(listOf(50, 1))).toBe(false)
    // a single hostile-sized membership (the CORD-05 bundle ceiling is 256
    // channels) overflows the WHOLE list by itself (measured ≈92,029 bytes):
    expect(canonicalBytes(listOf(1, MAX_CHANNELS_IN_BUNDLE)).length).toBeGreaterThan(NIP44_MAX_PLAINTEXT)
    // §8's rule: a client MUST verify the serialized List fits before
    // publishing, not merely count to 50.
  })
})

describe('limits — invite fragment sizes (CORD-05 §3)', () => {
  it('the common (stock) invite fragment is 46 characters — comfortably inside any length-restricted platform', () => {
    const frag = encodeFragment(randomBytes(32), 'stock')
    expect(frag.length).toBe(46) // ceil(34 bytes / 3) * 4, unpadded
  })

  it('even a maximal fragment (3 verbatim literals) stays link-sized', () => {
    const long = 'ws://a-quite-long-relay-hostname.example.org:8443'
    const frag = encodeFragment(randomBytes(32), [long, long, long])
    expect(frag.length).toBeLessThan(300)
  })
})

describe('limits — genesis and metadata stay small (CORD-02 §6: "the Control Plane is meant to stay small")', () => {
  it('a maximal metadata edition (64-byte name, 10000-byte description, 5 relays, icon+banner, custom) fits with room', () => {
    const ownerSk = randomBytes(32)
    const cidHex = bytesToHex(communityId(hexToBytes(pubkeyOf(ownerSk)), randomBytes(32)))
    const blob = () => ({ url: 'https://blossom.example/' + bytesToHex(randomBytes(24)), key: bytesToHex(randomBytes(32)), nonce: bytesToHex(randomBytes(12)), hash: bytesToHex(randomBytes(32)) })
    const rumor = makeRumor({
      kind: 3308,
      pubkey: pubkeyOf(ownerSk),
      content: JSON.stringify({
        name: 'n'.repeat(64),
        description: 'd'.repeat(10_000),
        relays: Array.from({ length: 5 }, (_, i) => `wss://relay-${i}.example.org/nostr`),
        icon: blob(), banner: blob(),
        custom: { rules: 'r'.repeat(2000), 'vector/theme': 'dark' },
      }),
      tags: [['vsk', '0'], ['eid', cidHex], ['ev', '1']],
      created_at: 1,
    })
    const sealBytes = envelopeFits(rumor, ownerSk)
    expect(sealBytes).toBeLessThan(NIP44_CAP / 2)
  })
})
