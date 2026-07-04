# Concord Event Examples

**Non-normative.** One example per event kind in the frozen registry (CORD-02, Appendix B). The CORD documents are the source of truth; if an example here disagrees with a CORD, the CORD wins.

Conventions used throughout:

- `<angle brackets>` are placeholders. Keys, ids, and hashes are lowercase hex (x-only pubkeys and ids are 32 bytes / 64 hex chars) unless noted.
- `nip44_encrypt(key, {...})` stands for the NIP-44 ciphertext of the serialized inner event — shown structurally so the nesting is readable.
- Rumors (the innermost events) are **unsigned** and carry no `sig`; the seal carries the author's real signature (CORD-01).
- `["ms", "<0..999>"]` is the sub-second remainder; true event time is `created_at * 1000 + ms` (CORD-02 §4).
- Examples are illustrative, not verifiable test vectors: ids, signatures, and derived addresses are placeholders, not real derivations.

## Contents

| Kind | Function | Example |
|---|---|---|
| 1059 | Gift wrap (durable envelope) | [§1.1](#11-kind-1059--the-wrap-encrypted-seal) |
| 20013 | Encrypted seal | [§1.1](#11-kind-1059--the-wrap-encrypted-seal) |
| 20014 | Plaintext seal (Control Plane) | [§1.2](#12-kind-20014--the-plaintext-seal) |
| 21059 | Ephemeral gift wrap | [§1.3](#13-kind-21059--the-ephemeral-wrap) |
| 9 | Message | [§2.1](#21-kind-9--message) |
| 7 | Reaction | [§2.2](#22-kind-7--reaction) |
| 5 | Delete | [§2.3](#23-kind-5--delete) |
| 3302 | Edit | [§2.4](#24-kind-3302--edit) |
| 3310 | WebXDC peer signal | [§2.5](#25-kind-3310--webxdc-peer-signal) |
| 3311 | Typing indicator (ephemeral) | [§2.6](#26-kind-3311--typing-indicator) |
| 3306 | Join / Leave | [§3.1](#31-kind-3306--join--leave) |
| 3309 | Kick | [§3.2](#32-kind-3309--kick) |
| 3312 | Guestbook snapshot | [§3.3](#33-kind-3312--guestbook-snapshot) |
| 3308 | Control edition (per `vsk`) | [§4](#4-control-plane--kind-3308-editions) |
| 3303 | Rekey blobs | [§5](#5-rekeys--kind-3303) |
| 33301 | Public invite bundle | [§6.1](#61-kind-33301--public-invite-bundle) |
| 13302 | Community List | [§6.2](#62-kind-13302--community-list) |
| 13303 | Invite List | [§6.3](#63-kind-13303--invite-list) |

Retired kinds (`3300, 3301, 3304, 3305, 3307, 23308`) have no examples: their numbers are burned, never reused (CORD-02, Appendix B).

## 1. The envelope

Every durable plane event is the same three-layer shape (CORD-01): a kind `1059` **wrap** signed by the plane's derived stream key, containing a **seal** signed by the author's real key, containing the unsigned **rumor** that carries the functional kind. Sections 2–5 show only rumors; each rides inside this envelope at its plane's address.

### 1.1 Kind 1059 — the wrap, encrypted seal

Chat, Guestbook, and rekey planes use the **encrypted seal** (kind `20013`): the rumor is NIP-44-encrypted *again* inside the already-encrypted wrap, so it can never be lifted out as a standalone public event (CORD-02 §5).

```jsonc
{
  "id": "<wrap id>",
  "kind": 1059,
  "pubkey": "<plane's stream pubkey>",            // e.g. channel_pk, guestbook_pk (CORD-02 §4)
  "content": nip44_encrypt(conv_key, {            // conv_key = NIP-44 self-ECDH of the stream key
    "id": "<seal id>",
    "kind": 20013,                                // encrypted seal
    "pubkey": "<author's real pubkey>",
    "content": nip44_encrypt(conv_key, {
      "id": "<rumor id>",
      "kind": 9,                                  // the functional kind (any §2–§5 rumor)
      "pubkey": "<author's real pubkey>",
      "content": "Hey chat!",
      "tags": [
        ["channel", "<channel_id>"],
        ["epoch", "0"],
        ["ms", "417"]
      ],
      "created_at": 1686840217
    }),
    "tags": [],
    "created_at": 1686840217,
    "sig": "<author's real signature>"
  }),
  "tags": [
    ["p", "<random ephemeral pubkey>"]            // ephemeral "p", fixed author — NIP-59 reversed (CORD-01)
  ],
  "created_at": 1686840217,
  "sig": "<stream key signature>"
}
```

### 1.2 Kind 20014 — the plaintext seal

The Control Plane **only** (CORD-02 §5). Same wrap, but the seal's `content` holds the rumor verbatim rather than ciphertext, so a compaction can re-wrap the signed edition into a new epoch with the signature intact (CORD-06). See §4 for the full Control edition example inside this seal.

```jsonc
{
  "kind": 1059,
  "pubkey": "<control_pk>",
  "content": nip44_encrypt(conv_key, {
    "kind": 20014,                                // plaintext seal
    "pubkey": "<actor's real pubkey>",
    "content": { /* the kind 3308 rumor verbatim, §4 — an object, not a ciphertext string */ },
    "tags": [],
    "created_at": 1686840217,
    "sig": "<actor's real signature>"
  }),
  "tags": [ ["p", "<random ephemeral pubkey>"] ],
  "created_at": 1686840217,
  "sig": "<control stream signature>"
}
```

### 1.3 Kind 21059 — the ephemeral wrap

Identical structure to `1059`, but relays MUST NOT store it: broadcast to live subscribers and gone. Used only for the typing indicator (§2.6).

```jsonc
{
  "kind": 21059,
  "pubkey": "<channel_pk>",
  "content": nip44_encrypt(conv_key, { /* kind 20013 seal around a kind 3311 rumor, §2.6 */ }),
  "tags": [ ["p", "<random ephemeral pubkey>"] ],
  "created_at": 1686840217,
  "sig": "<channel stream signature>"
}
```

## 2. Chat Plane rumors

All Chat rumors ride an encrypted seal (§1.1) at the Channel's address, and MUST commit `["channel", <channel_id>]` and `["epoch", <n>]` inside the author-signed rumor; a receiver checks both against the key that opened the wrap and drops a mismatch (CORD-03 §3).

### 2.1 Kind 9 — Message

NIP-29 shape: the `content` is the message text.

```jsonc
{
  "id": "<rumor id>",
  "kind": 9,
  "pubkey": "<author>",
  "content": "Hey chat!",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "417"]
  ],
  "created_at": 1686840217
}
```

A reply quotes the parent with a `q` tag (NIP-C7), citing the parent message's *rumor* id (never the outer wrap's, which differs per re-wrap):

```jsonc
{
  "kind": 9,
  "pubkey": "<author>",
  "content": "Welcome!",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "902"],
    ["q", "<parent message rumor id>", "", "<parent author>"]
  ],
  "created_at": 1686840304
}
```

### 2.2 Kind 7 — Reaction

NIP-25 shape: `content` is the reaction (`"+"`, an emoji, …), tags name the reacted-to message and its author.

```jsonc
{
  "kind": 7,
  "pubkey": "<reactor>",
  "content": "🔥",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "112"],
    ["e", "<message rumor id>"],
    ["p", "<message author>"]
  ],
  "created_at": 1686840350
}
```

### 2.3 Kind 5 — Delete

NIP-09 shape: `e` tags name the author's own rumors to delete, `content` an optional reason. A member's delete of their own past message is honored always — even after Dissolution (CORD-02 §9).

```jsonc
{
  "kind": 5,
  "pubkey": "<author>",
  "content": "",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "533"],
    ["e", "<own message rumor id>"]
  ],
  "created_at": 1686841000
}
```

### 2.4 Kind 3302 — Edit

The CORDs register the kind but don't yet pin its fields; this shape is illustrative. The `e` tag names the author's own message being edited, `content` the replacement text.

```jsonc
{
  "kind": 3302,
  "pubkey": "<author>",
  "content": "Hey chat! (fixed the typo)",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "781"],
    ["e", "<own message rumor id>"]
  ],
  "created_at": 1686840610
}
```

### 2.5 Kind 3310 — WebXDC peer signal

Realtime peer signaling for WebXDC apps. The CORDs register the kind but don't yet pin its payload; `content` is the app-level payload, opaque to the protocol.

```jsonc
{
  "kind": 3310,
  "pubkey": "<author>",
  "content": "<app payload>",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "266"]
  ],
  "created_at": 1686840700
}
```

### 2.6 Kind 3311 — Typing indicator

The one **ephemeral** action: same seal-and-rumor shape at the same Channel address, but the outer wrap is kind `21059` (§1.3), so relays never store it. Presence of the event is the signal; the rumor carries nothing.

```jsonc
{
  "kind": 3311,
  "pubkey": "<author>",
  "content": "",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "45"]
  ],
  "created_at": 1686840216
}
```

## 3. Guestbook Plane rumors

Encrypted seals (§1.1) at `guestbook_pk` (CORD-02 §5). The Guestbook coalesces flat — one final state per npub, latest wins by millisecond time, ties broken by the lower rumor id.

### 3.1 Kind 3306 — Join / Leave

Self-signed; the `content` is the verb. A Join MAY carry invite attribution echoed from the bundle (CORD-05 §1).

```jsonc
// Join, with optional invite attribution
{
  "kind": 3306,
  "pubkey": "<member>",
  "content": "join",
  "tags": [
    ["ms", "128"],
    ["invite", "<creator pubkey>", "Reddit"]      // optional, Joins only
  ],
  "created_at": 1719800000
}

// Leave
{
  "kind": 3306,
  "pubkey": "<member>",
  "content": "leave",
  "tags": [ ["ms", "660"] ],
  "created_at": 1722400000
}
```

### 3.2 Kind 3309 — Kick

Admin-signed, names its target, and cites the Grant it acts under (the `vac`, CORD-04 §5). Honored only if the signer holds `KICK` and strictly outranks the target.

```jsonc
{
  "kind": 3309,
  "pubkey": "<admin>",
  "content": "",
  "tags": [
    ["ms", "301"],
    ["p", "<target pubkey>"],
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"]
  ],
  "created_at": 1722410000
}
```

### 3.3 Kind 3312 — Guestbook snapshot

Refounder-signed, seeding the new epoch's Guestbook after a Refounding (CORD-02 §5). Present members only, chunked at 400 per event; all `n` chunks share one snapshot id and one timestamp.

```jsonc
{
  "kind": 3312,
  "pubkey": "<refounder>",
  "content": "[\"<member pubkey>\", \"<member pubkey>\", \"<member pubkey>\"]",
  "tags": [
    ["ms", "0"],
    ["snap", "<snapshot id>", "1", "2"]           // chunk 1 of 2
  ],
  "created_at": 1722500000
}
```

## 4. Control Plane — kind 3308 editions

Every authority action is a kind `3308` **edition** rumor inside a **plaintext seal** (§1.2) at `control_pk`. The tags carry the edition machinery (CORD-04 §1); the `content` is the entity's new state as JSON, its structure selected by `vsk`.

The common frame:

```jsonc
{
  "kind": 3308,
  "pubkey": "<actor's real pubkey>",
  "content": "<the entity's new state, per-vsk below, as a JSON string>",
  "tags": [
    ["vsk", "1"],                                 // entity type (registry below)
    ["eid", "<entity id, 32-byte hex>"],          // the stable coordinate
    ["ev",  "4"],                                 // this edition's version, climbs from 1
    ["ep",  "<prev edition hash>"],               // chain link, absent on the first edition
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"]  // absent when the owner acts
  ],
  "created_at": 1686840217
}
```

Per-`vsk` `content` payloads:

### vsk 0 — Community metadata (CORD-02 §6)

`eid` = the `community_id`. Gated by `MANAGE_METADATA`.

```jsonc
{
  "name": "Vector",
  "description": "Private messaging, no compromises.",
  "relays": ["wss://jskitty.com/nostr", "wss://asia.vectorapp.io/nostr"],
  "icon":   { "url": "https://blossom.example/…", "key": "<hex>", "nonce": "<hex>", "hash": "<sha256 hex>" },
  "banner": { "url": "https://blossom.example/…", "key": "<hex>", "nonce": "<hex>", "hash": "<sha256 hex>" },
  "custom": { "rules": "Be excellent to each other." }
}
```

### vsk 1 — Role (CORD-04 §2)

`eid` = the `role_id`, random 32 bytes minted at creation. Gated by `MANAGE_ROLES`.

```jsonc
{
  "role_id": "<role_id hex>",
  "name": "Moderator",
  "position": 2,
  "permissions": "40",                            // decimal string: 1<<3 KICK | 1<<5 MANAGE_MESSAGES
  "scope": { "kind": "server" },                  // or {"kind":"channel","channel_id":"<hex>"}
  "color": 15158332
}
```

### vsk 2 — Channel metadata (CORD-03 §2)

`eid` = the `channel_id`. Gated by `MANAGE_CHANNELS`.

```jsonc
{ "name": "general", "private": false }
```

A deletion is an edition setting the terminal flag:

```jsonc
{ "name": "general", "private": false, "deleted": true }
```

### vsk 3 — Grant (CORD-04 §2)

`eid` = `grant_locator(community_id, member)` (CORD-02 A.6). Honored only if the signer outranks every Role handed out; empty `role_ids` is a revoke.

```jsonc
{ "member": "<member pubkey>", "role_ids": ["<role_id hex>", "<role_id hex>"] }
```

### vsk 4 — Banlist (CORD-04 §4)

`eid` = `banlist_locator(community_id)` (CORD-02 A.6). The whole list, replaced entire on every edit; signer must hold `BAN`.

```jsonc
["<banned pubkey>", "<banned pubkey>"]
```

### vsk 8 — Invite-link registry (CORD-05 §5)

`eid` = `invite_links_locator(community_id, creator)` (CORD-02 A.6). Locators only, never tokens or URLs; honored while its author holds `CREATE_INVITE`.

```jsonc
["<bundle_id hex>", "<bundle_id hex>"]
```

### vsk 10 — Dissolved tombstone (CORD-02 §9)

Owner-signed, chainless, exempt from version discipline — published at `dissolved_pk`, not the Control Plane address. Presence of one valid owner-signed edition *is* the state.

```jsonc
{
  "kind": 3308,
  "pubkey": "<owner>",
  "content": "",
  "tags": [
    ["vsk", "10"],
    ["eid", "0000000000000000000000000000000000000000000000000000000000000000"]
    // chainless: no ev, no ep, no vac
  ],
  "created_at": 1725000000
}
```

Remaining `vsk` values carry no edition: `5` is reserved, `6`/`9` are claimed by the addressable invite marker (§6.1), `7` is retired.

## 5. Rekeys — kind 3303

Delivered at a **rekey address** derived from the *prior* secret (CORD-06 §2), wrapped and encrypted-sealed like any stream event. The seal's npub is the Rotator, whose authority a receiver verifies before accepting anything.

```jsonc
{
  "kind": 3303,
  "pubkey": "<rotator's real pubkey>",
  "content": "[ {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"}, {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"} ]",
  "tags": [
    ["scope",      "<channel_id hex>"],           // all-zero hex = the community_root (a Refounding)
    ["newepoch",   "3"],
    ["prevepoch",  "2"],
    ["prevcommit", "<epoch-key commitment hex, CORD-02 A.5>"],
    ["chunk",      "1", "2"]                      // this event is chunk 1 of 2 for the rotation
  ],
  "created_at": 1722500000
}
```

Each `wrapped` plaintext is exactly 72 bytes — `scope_id[32] ‖ epoch_be[8] ‖ new_key[32]` — NIP-44-encrypted under the Rotator↔recipient pairwise key; the recipient finds their blob by computing their `locator` (CORD-06 §2) and verifies the inner scope and epoch against the tags before accepting the key.

## 6. Outside the wrap

Three kinds relays see bare, signed by ordinary (or token-derived) keys.

### 6.1 Kind 33301 — public invite bundle (CORD-05 §2)

Addressable, at the token-derived coordinate, signed by the token-derived `bundle_signer`; a fetcher drops any event at the coordinate not carrying that signer's signature. The `vsk` tag marks it live (`6`) or a revocation tombstone (`9`).

```jsonc
// live bundle
{
  "kind": 33301,
  "pubkey": "<bundle_signer pubkey>",
  "content": "<nip44_encrypt(bundle_key, bundle)>",
  "tags": [
    ["d", "<bundle_id hex>"],
    ["vsk", "6"]
  ],
  "created_at": 1719800000,
  "sig": "<bundle_signer signature>"
}
```

The encrypted bundle's plaintext (CORD-05 §1):

```jsonc
{
  "community_id": "<hex>",
  "owner": "<owner pubkey>",
  "owner_salt": "<hex>",                          // verify: community_id == sha256("concord/community" || owner || salt)
  "community_root": "<hex>",
  "root_epoch": 0,
  "channels": [
    { "id": "<channel_id>", "key": "<hex>", "epoch": 1, "name": "testers" }
  ],
  "relays": ["wss://jskitty.com/nostr", "wss://relay.ditto.pub"],
  "name": "Vector",
  "icon": { "url": "https://blossom.example/…", "key": "<hex>", "nonce": "<hex>", "hash": "<sha256 hex>" },
  "expires_at": 1735689600000,                    // optional, unix ms
  "creator_npub": "<creator pubkey>",             // optional attribution
  "label": "Reddit"                               // optional attribution
}
```

Revoking the link re-posts the same coordinate as a tombstone:

```jsonc
{
  "kind": 33301,
  "pubkey": "<bundle_signer pubkey>",
  "content": "",
  "tags": [
    ["d", "<bundle_id hex>"],
    ["vsk", "9"]
  ],
  "created_at": 1722400000,
  "sig": "<bundle_signer signature>"
}
```

### 6.2 Kind 13302 — Community List (CORD-02 §8)

Replaceable, one per user, signed by their real key, NIP-44-encrypted to self. A client convenience, never Community state.

```jsonc
{
  "kind": 13302,
  "pubkey": "<member's real pubkey>",
  "content": "<nip44_encrypt(self, list)>",
  "tags": [],
  "created_at": 1722400000,
  "sig": "<member's real signature>"
}
```

The encrypted list's plaintext:

```jsonc
{
  "entries": [
    {
      "community_id": "<hex>",
      "seed":    { /* join material at the earliest epoch held — only ever moves backward on merge */ },
      "current": { /* join material at the freshest epoch — replaced on every Refounding or rename */ },
      "added_at": 1719800000000                   // ms
    }
  ],
  "tombstones": [
    { "community_id": "<hex>", "removed_at": 1722400000000 }
  ]
}
```

Join material is the bundle's membership subset: `community_id, owner, owner_salt, community_root, root_epoch, channels, relays, name` — never the icon, never the link fields.

### 6.3 Kind 13303 — Invite List (CORD-05 §4)

Replaceable, one per user, signed by their real key, NIP-44-encrypted to self: the creator's private bookkeeping for minted links.

```jsonc
{
  "kind": 13303,
  "pubkey": "<creator's real pubkey>",
  "content": "<nip44_encrypt(self, list)>",
  "tags": [],
  "created_at": 1722400000,
  "sig": "<creator's real signature>"
}
```

The encrypted list's plaintext:

```jsonc
{
  "entries": [
    {
      "token": "<hex>",                           // the link's secret AND its merge key
      "community_id": "<hex>",
      "url": "https://vectorapp.io/invite#<fragment>",
      "label": "Reddit",                          // optional
      "created_at": 1719800000,
      "expires_at": 1722400000                    // optional
    }
  ],
  "tombstones": [
    { "token": "<hex>", "community_id": "<hex>" }
  ]
}
```
