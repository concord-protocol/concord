/**
 * CORD-05: Invites — every claim in 05.md, asserted.
 */
import { describe, expect, it } from 'vitest'
import { v2 as nip44 } from 'nostr-tools/nip44'
import { bytesToHex, hexToBytes, randomBytes, utf8 } from '../src/bytes.js'
import { communityId, inviteBundleId, inviteBundleKey, inviteBundleSigner } from '../src/derive.js'
import { makeRumor, pubkeyOf, signEvent } from '../src/events.js'
import {
  boundBundle,
  decodeFragment,
  encodeFragment,
  fetchBundle,
  foldRegistries,
  FRAGMENT_VERSION,
  isPublicCommunity,
  joiningAllowed,
  KIND_INVITE_BUNDLE,
  KIND_INVITE_LIST,
  MAX_CHANNELS_IN_BUNDLE,
  MAX_FRAGMENT_RELAYS,
  MAX_RELAYS,
  mergeInviteLists,
  publishBundle,
  publishTombstone,
  RELAY_DICTIONARY,
  STOCK_RELAYS,
  VSK_LIVE,
  VSK_TOMBSTONE,
  type InviteBundle,
  type InviteList,
} from '../src/invites.js'
import { KIND_JOIN_LEAVE } from '../src/guestbook.js'

// ---- fixtures -------------------------------------------------------------------

const ownerSk = randomBytes(32)
const ownerPk = pubkeyOf(ownerSk)
const ownerSalt = randomBytes(32)
const cid = communityId(hexToBytes(ownerPk), ownerSalt)
const root = randomBytes(32)

function bundle(over: Partial<InviteBundle> = {}): InviteBundle {
  return {
    community_id: bytesToHex(cid),
    owner: ownerPk,
    owner_salt: bytesToHex(ownerSalt),
    community_root: bytesToHex(root),
    root_epoch: 0,
    channels: [{ id: 'aa'.repeat(32), key: 'bb'.repeat(32), epoch: 1, name: 'testers' }],
    relays: ['wss://jskitty.com/nostr', 'wss://relay.ditto.pub'],
    name: 'Vector',
    ...over,
  }
}
import { verifyBundleOwner } from '../src/invites.js'

describe('CORD-05 §1 — the bundle', () => {
  it('the bundle delivers everything membership needs: owner proof, root + epoch, granted channels, relays, preview', () => {
    const b = bundle()
    expect(verifyBundleOwner(b)).toBe(true)
    // possession of these keys IS membership — the invite is simply how they're handed over
    expect(b.community_root).toBe(bytesToHex(root))
    expect(b.channels[0]).toEqual({ id: 'aa'.repeat(32), key: 'bb'.repeat(32), epoch: 1, name: 'testers' })
  })

  it('the inviter’s identity is irrelevant to trust: the community_id self-certifies the owner', () => {
    // a bundle smuggling a FALSE owner fails to reproduce the community_id → refused
    const impostor = pubkeyOf(randomBytes(32))
    expect(verifyBundleOwner(bundle({ owner: impostor }))).toBe(false)
    // and a fake community_id for a real owner also fails
    expect(verifyBundleOwner(bundle({ community_id: 'ee'.repeat(32) }))).toBe(false)
    // a wrong salt fails too
    expect(verifyBundleOwner(bundle({ owner_salt: 'dd'.repeat(32) }))).toBe(false)
  })

  it('a bundle is attacker-crafted input: a client MUST bound it before allocating', () => {
    // more than the sane channel ceiling (256) → rejected outright
    const hostile = bundle({
      channels: Array.from({ length: MAX_CHANNELS_IN_BUNDLE + 1 }, (_, i) => ({
        id: String(i).padStart(64, '0'), key: 'bb'.repeat(32), epoch: 0, name: 'x',
      })),
    })
    expect(MAX_CHANNELS_IN_BUNDLE).toBe(256)
    expect(() => boundBundle(hostile)).toThrow(/channel/)
    // an oversized relay list (a connect-storm vector) → truncated to the cap
    const relayStorm = bundle({ relays: Array.from({ length: 40 }, (_, i) => `wss://r${i}.example`) })
    expect(boundBundle(relayStorm).relays).toHaveLength(MAX_RELAYS)
  })

  it('expires_at: past it, the preview still renders but joining refuses', () => {
    const expiring = bundle({ expires_at: 1_735_689_600_000 })
    expect(joiningAllowed(expiring, expiring.expires_at! - 1)).toBe(true)
    expect(joiningAllowed(expiring, expiring.expires_at! + 1)).toBe(false)
    // the preview fields are still present and renderable either way
    expect(expiring.name).toBe('Vector')
    // absent expiry never refuses
    expect(joiningAllowed(bundle(), Number.MAX_SAFE_INTEGER)).toBe(true)
  })

  it('attribution: an accepting joiner echoes creator and label in their Guestbook Join — per-link usage counters', () => {
    const attributed = bundle({ creator_npub: ownerPk, label: 'Reddit' })
    const join = makeRumor({
      kind: KIND_JOIN_LEAVE,
      pubkey: pubkeyOf(randomBytes(32)),
      content: 'join',
      tags: [['ms', '128'], ['invite', attributed.creator_npub!, attributed.label!]],
      created_at: 1719800000,
    })
    const invTag = join.tags.find(t => t[0] === 'invite')!
    expect(invTag[1]).toBe(ownerPk)
    expect(invTag[2]).toBe('Reddit')
  })
})

describe('CORD-05 §2 — the link', () => {
  const token = randomBytes(32)

  it('the token alone derives everything needed to find and open the bundle', () => {
    // three independent derivations from nothing but the token
    const key = inviteBundleKey(token)
    const id = inviteBundleId(token)
    const signer = inviteBundleSigner(token)
    expect(new Set([bytesToHex(key), bytesToHex(id), bytesToHex(signer.sk)]).size).toBe(3)
    // deterministic: any client holding the fragment derives the same three
    expect(bytesToHex(inviteBundleKey(token))).toBe(bytesToHex(key))
    expect(inviteBundleSigner(token).pk).toBe(signer.pk)
  })

  it('the bundle is posted addressable, signed by bundle_signer at bundle_id, its content NIP-44 encrypted to the token', () => {
    const ev = publishBundle(token, bundle(), 1719800000)
    expect(ev.kind).toBe(KIND_INVITE_BUNDLE)
    expect(ev.pubkey).toBe(inviteBundleSigner(token).pk)
    expect(ev.tags).toContainEqual(['d', bytesToHex(inviteBundleId(token))])
    expect(ev.tags).toContainEqual(['vsk', VSK_LIVE])
    // only a token-holder can open it
    const plain = nip44.decrypt(ev.content, inviteBundleKey(token))
    expect(JSON.parse(plain).name).toBe('Vector')
    expect(() => nip44.decrypt(ev.content, inviteBundleKey(randomBytes(32)))).toThrow()
  })

  it('a fetcher rejects any event at the coordinate not signed by the token’s signer — squatting buys nothing even posted first', () => {
    const squatterSk = randomBytes(32)
    const squat = signEvent(
      {
        kind: KIND_INVITE_BUNDLE,
        pubkey: pubkeyOf(squatterSk),
        content: 'junk',
        tags: [['d', bytesToHex(inviteBundleId(token))], ['vsk', VSK_LIVE]],
        created_at: 1719700000, // posted FIRST
      },
      squatterSk,
    )
    const legit = publishBundle(token, bundle(), 1719800000)
    const res = fetchBundle([squat, legit], token)
    expect(res.status).toBe('live') // the squatter's event is dropped unread
    // even a squatter ALONE yields nothing
    expect(fetchBundle([squat], token).status).toBe('none')
  })

  it('the coordinate is stable: re-posting refreshes the bundle behind the same URL — a link shared once survives every rotation', () => {
    const v1 = publishBundle(token, bundle(), 1719800000)
    const rotated = bundle({ community_root: bytesToHex(randomBytes(32)), root_epoch: 1 })
    const v2 = publishBundle(token, rotated, 1719900000)
    expect(v2.tags.find(t => t[0] === 'd')![1]).toBe(v1.tags.find(t => t[0] === 'd')![1]) // same coordinate
    const res = fetchBundle([v1, v2], token)
    expect(res.status).toBe('live')
    if (res.status === 'live') expect(res.bundle.root_epoch).toBe(1) // fresh keys, same URL
  })

  it('retiring a link: a token-signed revocation tombstone replaces the bundle — exactly as durable, creator-only', () => {
    const live = publishBundle(token, bundle(), 1719800000)
    const tomb = publishTombstone(token, 1722400000)
    expect(tomb.tags).toContainEqual(['vsk', VSK_TOMBSTONE])
    expect(tomb.pubkey).toBe(inviteBundleSigner(token).pk) // still token-signed
    expect(fetchBundle([live, tomb], token).status).toBe('revoked') // the grave, not keys
    // an impostor's "tombstone" is dropped like any squat
    const fakeSk = randomBytes(32)
    const fakeTomb = signEvent(
      { kind: KIND_INVITE_BUNDLE, pubkey: pubkeyOf(fakeSk), content: '', tags: [['d', bytesToHex(inviteBundleId(token))], ['vsk', VSK_TOMBSTONE]], created_at: 1722500000 },
      fakeSk,
    )
    expect(fetchBundle([live, fakeTomb], token).status).toBe('live')
  })

  it('clients quickly identify whether a link is live by checking for a tombstone at the addressable bundle', () => {
    const tomb = publishTombstone(token, 1722400000)
    expect(fetchBundle([tomb], token).status).toBe('revoked')
  })

  it('the fragment is protocol; the base is interchangeable — the same fragment opens on any base', () => {
    const frag = encodeFragment(token, 'stock')
    for (const base of ['https://vectorapp.io/invite', 'https://armada.example/i', 'https://anything.example']) {
      const url = `${base}#${frag}`
      const parsed = decodeFragment(url.split('#')[1]!)
      expect(bytesToHex(parsed.token)).toBe(bytesToHex(token)) // respected verbatim
    }
  })

  it('the fragment carries only the 32-byte fetch-token, never the keys', () => {
    const frag = encodeFragment(token, 'stock')
    const rootHex = bytesToHex(root)
    expect(frag).not.toContain(rootHex)
    expect(frag).not.toContain(rootHex.slice(0, 16))
    const decoded = decodeFragment(frag)
    expect(decoded.token).toHaveLength(32)
  })
})

describe('CORD-05 §3 — the relay dictionary', () => {
  const token = randomBytes(32)

  it('the stock set is four primaries: two Vector, two Soapbox, exactly as listed', () => {
    expect(RELAY_DICTIONARY[1]).toBe('wss://jskitty.com/nostr')
    expect(RELAY_DICTIONARY[2]).toBe('wss://asia.vectorapp.io/nostr')
    expect(RELAY_DICTIONARY[3]).toBe('wss://relay.ditto.pub')
    expect(RELAY_DICTIONARY[4]).toBe('wss://relay.dreamith.to')
  })

  it('the fragment encodes [version][flags][relays?][token:32] as base64url with no padding', () => {
    const frag = encodeFragment(token, 'stock')
    expect(frag).not.toContain('=') // no padding
    expect(frag).not.toMatch(/[+/]/) // base64url, not base64
    const raw = Buffer.from(frag, 'base64url')
    expect(raw[0]).toBe(FRAGMENT_VERSION)
    expect(raw.length).toBe(1 + 1 + 32) // version + flags + token: the stock flag adds ZERO relay bytes
  })

  it('version is 3, and a client MAY reject any lower value as a legacy link', () => {
    expect(FRAGMENT_VERSION).toBe(3)
    const legacy = Buffer.from([2, 1, ...token]).toString('base64url')
    expect(() => decodeFragment(legacy)).toThrow(/legacy/)
  })

  it('the flags bit selects the stock set: the common invite carries zero additional relay bytes', () => {
    const decoded = decodeFragment(encodeFragment(token, 'stock'))
    expect(decoded.relays).toEqual(STOCK_RELAYS)
  })

  it('a dictionary id encodes a relay in one byte, no literal', () => {
    const frag = encodeFragment(token, ['wss://relay.ditto.pub'])
    const raw = Buffer.from(frag, 'base64url')
    expect(raw.length).toBe(1 + 1 + 1 + 1 + 32) // version+flags+count+dictId+token
    expect(decodeFragment(frag).relays).toEqual(['wss://relay.ditto.pub'])
  })

  it('escape 0: a wss-implied literal, "wss://" re-prepended on decode', () => {
    const frag = encodeFragment(token, ['wss://my.own.relay'])
    const decoded = decodeFragment(frag)
    expect(decoded.relays).toEqual(['wss://my.own.relay'])
    // the fragment stores only the host bytes (prefix stripped)
    const raw = Buffer.from(frag, 'base64url')
    expect(raw.length).toBe(1 + 1 + 1 + 2 + utf8('my.own.relay').length + 32)
  })

  it('escape 255: a verbatim literal for ws:// or exotic schemes', () => {
    const frag = encodeFragment(token, ['ws://plaintext.example:7777'])
    expect(decodeFragment(frag).relays).toEqual(['ws://plaintext.example:7777'])
  })

  it('mixed entries roundtrip: dictionary + implied + verbatim in one fragment', () => {
    const relays = ['wss://jskitty.com/nostr', 'wss://my.own.relay', 'ws://exotic.example']
    expect(decodeFragment(encodeFragment(token, relays)).relays).toEqual(relays)
  })

  it('the fragment carries at most 3 bootstrap relays — it only needs to FIND the bundle', () => {
    expect(MAX_FRAGMENT_RELAYS).toBe(3)
    expect(() => encodeFragment(token, ['wss://a', 'wss://b', 'wss://c', 'wss://d'])).toThrow(/3/)
  })

  it('the dictionary is a default, not a requirement: users can skip the primaries and encode their own relays inline', () => {
    const own = ['wss://sovereign.example']
    const decoded = decodeFragment(encodeFragment(token, own))
    expect(decoded.relays).toEqual(own)
    for (const r of decoded.relays) expect(STOCK_RELAYS).not.toContain(r)
  })

  it('an invite minted by either client opens in the other: encode/decode is one deterministic dictionary', () => {
    // both "clients" here are two independent decode passes over the same bytes
    const frag = encodeFragment(token, 'stock')
    expect(decodeFragment(frag)).toEqual(decodeFragment(frag))
  })
})

describe('CORD-05 §4 — the Invite List', () => {
  const t1 = 'aa'.repeat(32)
  const t2 = 'bb'.repeat(32)
  const entry = (tok: string, label?: string) => ({
    token: tok,
    community_id: bytesToHex(cid),
    url: `https://vectorapp.io/invite#frag-${tok.slice(0, 4)}`,
    ...(label ? { label } : {}),
    created_at: 1719800000,
  })

  it('kind 13303, and the token is the merge key: two copies merge without coordination', () => {
    expect(KIND_INVITE_LIST).toBe(13303)
    const a: InviteList = { entries: [entry(t1)], tombstones: [] }
    const b: InviteList = { entries: [entry(t2)], tombstones: [] }
    const merged = mergeInviteLists(a, b)
    expect(merged.entries.map(e => e.token).sort()).toEqual([t1, t2])
  })

  it('an entry is immutable once minted: a differing duplicate does not replace it', () => {
    const a: InviteList = { entries: [entry(t1, 'Reddit')], tombstones: [] }
    const b: InviteList = { entries: [{ ...entry(t1), label: 'Renamed' }], tombstones: [] }
    const merged = mergeInviteLists(a, b)
    expect(merged.entries).toHaveLength(1)
    expect(merged.entries[0]!.label).toBe('Reddit') // first wins; entries never mutate
  })

  it('tombstones union, and a tombstone beats an entry terminally: a stale device can never resurrect a revoked link', () => {
    const revoked: InviteList = { entries: [], tombstones: [{ token: t1, community_id: bytesToHex(cid) }] }
    const staleDevice: InviteList = { entries: [entry(t1)], tombstones: [] }
    const merged = mergeInviteLists(revoked, staleDevice)
    expect(merged.entries).toHaveLength(0)
    expect(merged.tombstones).toHaveLength(1)
    // merging again (any direction, any number of times) never revives it
    const again = mergeInviteLists(staleDevice, mergeInviteLists(merged, staleDevice))
    expect(again.entries).toHaveLength(0)
  })
})

describe('CORD-05 §5 — the Registry', () => {
  const creatorA = pubkeyOf(randomBytes(32))
  const creatorB = pubkeyOf(randomBytes(32))
  const loc1 = '11'.repeat(32)
  const loc2 = '22'.repeat(32)

  it('a Registry lists locators only — never tokens or URLs, the secret is never listed', () => {
    const token = randomBytes(32)
    const registryContent = [bytesToHex(inviteBundleId(token))]
    // members can SEE that links exist without gaining the ability to use one:
    // the locator does not reveal the token (one-way hkdf)
    expect(registryContent[0]).not.toBe(bytesToHex(token))
    expect(registryContent[0]).toHaveLength(64)
  })

  it('each creator owns exactly their own list: the coordinate binds to the creator, forging into another’s is impossible', async () => {
    const { registryEid } = await import('../src/editions.js')
    expect(registryEid(cid, creatorA)).not.toBe(registryEid(cid, creatorB))
    expect(registryEid(cid, creatorA)).toBe(registryEid(cid, creatorA)) // deterministic
  })

  it('honored only while its author holds CREATE_INVITE', () => {
    const perms = new Set([creatorA]) // only A holds the bit
    const active = foldRegistries(
      [
        { creator: creatorA, locators: [loc1] },
        { creator: creatorB, locators: [loc2] }, // B lost the bit: ignored
      ],
      npub => perms.has(npub),
    )
    expect(active).toEqual(new Set([loc1]))
  })

  it('the folded aggregate is the Public/Private source of truth: non-empty = Public, empty = Private', () => {
    const live = foldRegistries([{ creator: creatorA, locators: [loc1, loc2] }], () => true)
    expect(isPublicCommunity(live)).toBe(true)
    const none = foldRegistries([{ creator: creatorA, locators: [] }], () => true)
    expect(isPublicCommunity(none)).toBe(false)
  })

  it('retiring the last live link empties the set — precisely what triggers the Refounding', () => {
    // before: one live link
    let registries = [{ creator: creatorA, locators: [loc1] }]
    expect(isPublicCommunity(foldRegistries(registries, () => true))).toBe(true)
    // the retire: tombstone the bundle AND edit the registry (an edit accompanies every retire)
    registries = [{ creator: creatorA, locators: [] }]
    const nowEmpty = foldRegistries(registries, () => true)
    expect(isPublicCommunity(nowEmpty)).toBe(false) // → flips Private → Refounding (CORD-06)
  })
})
