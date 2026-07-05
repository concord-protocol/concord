/**
 * Spec-document consistency: the frozen tables printed in the CORD markdown
 * (kinds, vsk registry, permission bits, labels, the relay dictionary, the
 * protocol constants) must match the reference model the other suites proved.
 * This pins the DOCUMENTS to the evidence.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { VSK } from '../src/editions.js'
import { MAX_FUTURE_MS, SNAPSHOT_CHUNK } from '../src/guestbook.js'
import { MAX_MEMBERSHIPS, NIP44_MAX_PLAINTEXT } from '../src/communityList.js'
import { FRAGMENT_VERSION, MAX_FRAGMENT_RELAYS, RELAY_DICTIONARY } from '../src/invites.js'
import { RECIPIENTS_PER_EVENT, WRAPPED_PLAINTEXT_LEN } from '../src/rekey.js'
import { MAX_ROLES_PER_COMMUNITY, MAX_ROLES_PER_MEMBER, NAME_CAP_BYTES, PERM } from '../src/roster.js'
import { EDITION_HASH_LABEL } from '../src/editions.js'

const root = join(__dirname, '..')
const doc = (name: string) => readFileSync(join(root, name), 'utf8')
const cord01 = doc('01.md')
const cord02 = doc('02.md')
const cord03 = doc('03.md')
const cord04 = doc('04.md')
const cord05 = doc('05.md')
const cord06 = doc('06.md')
const readme = doc('README.md')

describe('README', () => {
  it('lists all six CORD documents, and each file exists', () => {
    for (const n of ['01', '02', '03', '04', '05', '06']) {
      expect(doc(`${n}.md`).length).toBeGreaterThan(0)
    }
    expect(readme).toContain('CORD')
  })
})

describe('CORD-01 — stated constants', () => {
  it('names the wrap kind 1059 and seal kinds 20013/20014', () => {
    expect(cord01).toContain('1059')
    expect(cord01).toContain('20013')
    expect(cord01).toContain('20014')
  })

  it('pins the plaintext-seal byte discipline: the rumor rides as an exact string, never re-serialized', () => {
    expect(cord01).toContain('byte-verbatim')
    expect(cord01).toMatch(/never re-serialize/)
  })
})

describe('CORD-02 — frozen kind registry (Appendix B)', () => {
  it('the durable kind table matches the model', () => {
    const rows: [number, RegExp][] = [
      [9, /\|\s*9\s*\|\s*Message/],
      [7, /\|\s*7\s*\|\s*Reaction/],
      [5, /\|\s*5\s*\|\s*Delete/],
      [3302, /\|\s*3302\s*\|\s*Edit/],
      [3303, /\|\s*3303\s*\|\s*Rekey blobs/],
      [3306, /\|\s*3306\s*\|\s*Join \/ Leave/],
      [3308, /\|\s*3308\s*\|\s*Control edition/],
      [3309, /\|\s*3309\s*\|\s*Kick/],
      [3310, /\|\s*3310\s*\|\s*WebXDC/],
      [3312, /\|\s*3312\s*\|\s*Guestbook snapshot/],
    ]
    for (const [, re] of rows) expect(cord02).toMatch(re)
  })

  it('the retired kinds are listed as burned: 3300, 3301, 3304, 3305, 3307, 23308', () => {
    expect(cord02).toMatch(/3300, 3301, 3304, 3305, 3307\s*\|\s*\*retired\*/)
    expect(cord02).toMatch(/23308\s*\|\s*\*retired\*/)
    // and the model claims none of them
    const used = [9, 7, 5, 1059, 21059, 20013, 20014, 3302, 3303, 3306, 3308, 3309, 3310, 3311, 3312, 33301, 13302, 13303]
    for (const burned of [3300, 3301, 3304, 3305, 3307, 23308]) expect(used).not.toContain(burned)
  })

  it('the ephemeral typing indicator is 3311 in a 21059 wrap', () => {
    expect(cord02).toMatch(/\|\s*3311\s*\|\s*Typing indicator/)
    expect(cord02).toContain('21059')
  })

  it('the bare kinds are 33301, 13302, 13303', () => {
    expect(cord02).toMatch(/\|\s*33301\s*\|/)
    expect(cord02).toMatch(/\|\s*13302\s*\|/)
    expect(cord02).toMatch(/\|\s*13303\s*\|/)
  })

  it('the vsk registry rows match the model', () => {
    expect(cord02).toMatch(/\|\s*0\s*\|\s*Community metadata/)
    expect(cord02).toMatch(/\|\s*1\s*\|\s*Role/)
    expect(cord02).toMatch(/\|\s*2\s*\|\s*Channel metadata/)
    expect(cord02).toMatch(/\|\s*3\s*\|\s*Grant/)
    expect(cord02).toMatch(/\|\s*4\s*\|\s*Banlist/)
    expect(cord02).toMatch(/\|\s*5\s*\|\s*\*reserved\*/)
    expect(cord02).toMatch(/\|\s*6, 9\s*\|\s*\*claimed\*/)
    expect(cord02).toMatch(/\|\s*7\s*\|\s*\*retired\*/)
    expect(cord02).toMatch(/\|\s*8\s*\|\s*Invite-link registry/)
    expect(cord02).toMatch(/\|\s*10\s*\|\s*Dissolved tombstone/)
    expect(VSK.DISSOLVED).toBe(10)
  })

  it('the A.6 label table carries every label the model derives with', () => {
    for (const label of [
      'concord/channel', 'concord/control', 'concord/rekey-pseudonym',
      'concord/base-rekey-pseudonym', 'concord/recipient-pseudonym',
      'concord/guestbook', 'concord/dissolved', 'concord/grant',
      'concord/banlist', 'concord/invite-links', 'concord/invite-key',
      'concord/invite-locator', 'concord/invite-signer',
    ]) {
      expect(cord02).toContain('`' + label + '`')
    }
  })

  it('stated constants match the model: 400/chunk, 1 hour skew, 64-byte names, 50 memberships, 65,535 NIP-44 cap', () => {
    expect(cord02).toContain('400 members per event')
    expect(SNAPSHOT_CHUNK).toBe(400)
    expect(cord02).toMatch(/one hour/)
    expect(MAX_FUTURE_MS).toBe(60 * 60 * 1000)
    expect(cord02).toContain('**64 bytes**')
    expect(NAME_CAP_BYTES).toBe(64)
    expect(cord02).toContain('**50 memberships**')
    expect(MAX_MEMBERSHIPS).toBe(50)
    expect(cord02).toContain('65,535 bytes')
    expect(NIP44_MAX_PLAINTEXT).toBe(65535)
    expect(cord02).toContain('**10000 bytes**')
  })

  it('pins the stress findings: malformed ms dropped, grinding residual named, the byte cap is the law, tombstoned entries persist', () => {
    expect(cord02).toMatch(/`ms` tag outside `0\.\.999` is malformed/)
    expect(cord02).toContain('author-grindable')
    expect(cord02).toMatch(/MUST verify the serialized List fits/)
    expect(cord02).toMatch(/tombstoned entry stays \*in\* the document/)
    expect(cord02).toMatch(/MUST enforce the cap at every layer/)
    expect(cord02).toMatch(/counter starting at 0/)
  })
})

describe('CORD-04 — frozen permission bits', () => {
  it('the bit table rows match the model exactly', () => {
    const rows: [bigint, string][] = [
      [PERM.MANAGE_ROLES, String.raw`\|\s*1<<0\s*\|\s*MANAGE_ROLES`],
      [PERM.MANAGE_CHANNELS, String.raw`\|\s*1<<1\s*\|\s*MANAGE_CHANNELS`],
      [PERM.MANAGE_METADATA, String.raw`\|\s*1<<2\s*\|\s*MANAGE_METADATA`],
      [PERM.KICK, String.raw`\|\s*1<<3\s*\|\s*KICK`],
      [PERM.BAN, String.raw`\|\s*1<<4\s*\|\s*BAN`],
      [PERM.MANAGE_MESSAGES, String.raw`\|\s*1<<5\s*\|\s*MANAGE_MESSAGES`],
      [PERM.CREATE_INVITE, String.raw`\|\s*1<<6\s*\|\s*CREATE_INVITE`],
      [PERM.VIEW_AUDIT_LOG, String.raw`\|\s*1<<8\s*\|\s*VIEW_AUDIT_LOG`],
      [PERM.MENTION_EVERYONE, String.raw`\|\s*1<<9\s*\|\s*MENTION_EVERYONE`],
    ]
    for (const [bit, re] of rows) {
      expect(cord04).toMatch(new RegExp(re))
      const shift = new RegExp(re).source.match(/1<<(\d+)/)![1]!
      expect(bit).toBe(1n << BigInt(shift)) // the doc's shift equals the model's bit
    }
    expect(cord04).toMatch(/1<<7\s*\|\s*retired \(was MANAGE_INVITES\)/)
    expect(cord04).toMatch(/1<<10, 1<<11, 1<<12\s*\|\s*reserved/)
  })

  it('the edition hash domain label is exactly the one in the doc', () => {
    expect(cord04).toContain('vector-community/v1/edition')
    expect(EDITION_HASH_LABEL).toBe('vector-community/v1/edition')
  })

  it('the caps match: 64 roles per member, 100 per community, 64-byte role names', () => {
    expect(cord04).toContain('at most 64 Roles')
    expect(cord04).toContain('at most 100 Roles')
    expect(MAX_ROLES_PER_MEMBER).toBe(64)
    expect(MAX_ROLES_PER_COMMUNITY).toBe(100)
    expect(cord04).toContain('≤ 64 bytes')
  })

  it('pins the stress findings: position 0 unmintable (owner included), vac hash checked, banlist ceiling honest', () => {
    expect(cord04).toMatch(/no Role may ever claim position 0/)
    expect(cord04).toMatch(/binds the owner too/)
    expect(cord04).toMatch(/hash does not match .* parks exactly like an unsynced one/)
    expect(cord04).toContain('**500 npubs**')
    expect(cord04).not.toMatch(/pubkeys, unbounded/) // the old literal claim is retired
  })
})

describe('CORD-05 — the relay dictionary', () => {
  it('the four stock relays match the model, id for id', () => {
    expect(cord05).toMatch(/1 = wss:\/\/jskitty\.com\/nostr/)
    expect(cord05).toMatch(/2 = wss:\/\/asia\.vectorapp\.io\/nostr/)
    expect(cord05).toMatch(/3 = wss:\/\/relay\.ditto\.pub/)
    expect(cord05).toMatch(/4 = wss:\/\/relay\.dreamith\.to/)
    expect(RELAY_DICTIONARY[1]).toBe('wss://jskitty.com/nostr')
    expect(RELAY_DICTIONARY[2]).toBe('wss://asia.vectorapp.io/nostr')
    expect(RELAY_DICTIONARY[3]).toBe('wss://relay.ditto.pub')
    expect(RELAY_DICTIONARY[4]).toBe('wss://relay.dreamith.to')
  })

  it('the fragment format constants match: version 3, ≤ 3 bootstrap relays, escapes 0 and 255', () => {
    expect(cord05).toMatch(/it's `3`/)
    expect(FRAGMENT_VERSION).toBe(3)
    expect(cord05).toContain('at most **3 bootstrap relays**')
    expect(MAX_FRAGMENT_RELAYS).toBe(3)
    expect(cord05).toMatch(/^0\s+a wss-implied literal/m)
    expect(cord05).toMatch(/^255\s+a verbatim literal/m)
    expect(cord05).toMatch(/1\.\.=254\s+a dictionary id/)
  })

  it('a channel ceiling of 256 is stated for hostile bundles', () => {
    expect(cord05).toContain('256')
  })
})

describe('CORD-06 — stated constants', () => {
  it('120 recipients per event, 72-byte wrapped plaintext', () => {
    expect(cord06).toContain('120 participants per-event')
    expect(RECIPIENTS_PER_EVENT).toBe(120)
    expect(cord06).toContain('72 bytes')
    expect(WRAPPED_PLAINTEXT_LEN).toBe(72)
    expect(cord06).toContain('scope_id[32] ‖ epoch_be[8] ‖ new_key[32]')
  })
})

describe('CORD-03 — stated constants', () => {
  it('the 64-byte name cap is restated as the protocol-wide cap', () => {
    expect(cord03).toContain('name ≤ 64 bytes')
  })
})

describe('examples.md — non-normative examples stay consistent with the registry', () => {
  const examples = doc('examples.md')
  it('covers every kind in the frozen registry', () => {
    for (const kind of ['1059', '20013', '20014', '21059', '9', '7', '5', '3302', '3310', '3311', '3306', '3309', '3312', '3308', '3303', '33301', '13302', '13303']) {
      expect(examples).toMatch(new RegExp(`\\|\\s*${kind}\\s*\\|`))
    }
  })
  it('declares the CORDs win on disagreement, and rumors are unsigned', () => {
    expect(examples).toContain('the CORD wins')
    expect(examples).toMatch(/unsigned/)
  })
})
