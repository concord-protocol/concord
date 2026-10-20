# Concord Event Examples

**Non-normative.** Examples of every event kind in the frozen registry (CORD-02, Appendix B), and of each form a kind takes: every Control sub-kind, rotations and deliveries, a post at a restricted Channel's writer address. The CORD documents are the source of truth; if an example here disagrees with a CORD, the CORD wins.

Conventions used throughout:

- `<angle brackets>` are placeholders. Keys, ids, and hashes are lowercase hex (x-only pubkeys and ids are 32 bytes / 64 hex chars) unless noted.
- `nip44_encrypt(key, {...})` stands for the NIP-44 ciphertext of the serialized inner event — shown structurally so the nesting is readable.
- Rumors (the innermost events) are **unsigned** and carry no `sig`; the seal carries the author's real signature (CORD-01).
- `["ms", "<0..999>"]` is the sub-second remainder; true event time is `created_at * 1000 + ms` (CORD-02 §4).
- Examples are illustrative, not verifiable test vectors: ids, signatures, and derived addresses are placeholders, not real derivations, except where a section says it holds real values (§4.1, §5.3, and CORD-02 A.6's coordinate table).
- A reader finds a tag by name, and tag order carries no meaning except where a CORD says (the first `wcert`, the first `mint`); Vector appends `ms` last. JSON key order and whitespace carry none either: an edition's hash covers its `content` bytes as carried (CORD-04 §1).

## Contents

| Kind | Function | Example |
|---|---|---|
| 1059 | Gift wrap (durable envelope) | [§1.1](#11-kind-1059--the-wrap-encrypted-seal) |
| 20013 | Encrypted seal | [§1.1](#11-kind-1059--the-wrap-encrypted-seal) |
| 20014 | Plaintext seal (Control Plane) | [§1.2](#12-kind-20014--the-plaintext-seal) |
| 21059 | Ephemeral gift wrap | [§1.3](#13-kind-21059--the-ephemeral-wrap) |
| 9 | Message | [§2.1](#21-kind-9--message) |
| 1111 | Threaded reply | [§2.2](#22-kind-1111--threaded-reply) |
| 7 | Reaction | [§2.3](#23-kind-7--reaction) |
| 5 | Delete | [§2.4](#24-kind-5--delete) |
| 3302 | Edit | [§2.5](#25-kind-3302--edit) |
| 3310 | WebXDC peer signal | [§2.6](#26-kind-3310--webxdc-peer-signal) |
| 23311 | Typing indicator (ephemeral) | [§2.7](#27-kind-23311--typing-indicator) |
| 23313 | Voice presence (ephemeral) | [§2.8](#28-kind-23313--voice-presence) |
| 1740 | Timer notice | [§2.9](#29-kind-1740--timer-notice) |
| 23314 | Voice directive (ephemeral) | [§2.10](#210-kind-23314--voice-directive) |
| 9, 1111, … | A post at a restricted Channel's writer address | [§2.11](#211-restricted-channels--posting-at-a-writer-address) |
| 3306 | Join / Leave | [§3.1](#31-kind-3306--join--leave) |
| 3309 | Kick | [§3.2](#32-kind-3309--kick) |
| 3312 | Guestbook snapshot | [§3.3](#33-kind-3312--guestbook-snapshot) |
| 3314 | Timeout | [§3.4](#34-kind-3314--timeout) |
| 3308 | Control edition, the common frame (per `vsk`) | [§4](#4-control-plane--kind-3308-editions) |
| 3308 · vsk 0 | Community metadata | [§4 vsk 0](#vsk-0--community-metadata-cord-02-6) |
| 3308 · vsk 1 | Role, legacy | [§4 vsk 1](#vsk-1--role-legacy-cord-04-2) |
| 3308 · vsk 2 | Channel metadata | [§4 vsk 2](#vsk-2--channel-metadata-cord-03-2) |
| 3308 · vsk 3 | Grant | [§4 vsk 3](#vsk-3--grant-cord-04-2) |
| 3308 · vsk 4 | Banlist | [§4 vsk 4](#vsk-4--banlist-cord-04-4) |
| 3308 · vsk 8 | Invite-link registry | [§4 vsk 8](#vsk-8--invite-link-registry-cord-05-5) |
| 3308 · vsk 11 | Pin List | [§4 vsk 11](#vsk-11--pin-list-cord-04-7) |
| 3308 · vsk 13 | Role and `@everyone` | [§4 vsk 13](#vsk-13--role-and-everyone-cord-04-2) |
| 3308 · vsk 14 | ACL overwrite | [§4 vsk 14](#vsk-14--acl-overwrite-cord-04-8) |
| 3308 · vsk 15 | Category | [§4 vsk 15](#vsk-15--category-cord-03-4) |
| 3308 · vsk 16 | Tenure | [§4 vsk 16](#vsk-16--tenure-cord-04-9) |
| 3308 · vsk 17 | Channel sync | [§4 vsk 17](#vsk-17--channel-sync-cord-04-8) |
| 3308 · vsk 18 | Writers ledger | [§4 vsk 18](#vsk-18--writers-ledger-cord-03-1) |
| 3308 · vsk 10 | Dissolved tombstone | [§4 vsk 10](#vsk-10--dissolved-tombstone-cord-02-9) |
| 3308 · vsk 2–18 | Byte-exact contents, real values | [§4.1](#41-byte-exact-contents) |
| 3303 | Rekey blobs (rotations) | [§5.1](#51-rotations) |
| 3303 | Key deliveries: access, writer, certifier, history | [§5.2](#52-deliveries) |
| 3320 | Writer certificate preimage (never published) | [§5.3](#53-kind-3320--writer-certificate-preimage) |
| 33301 | Public invite bundle | [§6.1](#61-kind-33301--public-invite-bundle-cord-05-2) |
| 33302 | Community List | [§6.2](#62-kind-33302--community-list-cord-02-8) |
| 13303 | Invite List | [§6.3](#63-kind-13303--invite-list-cord-05-4) |
| 3313 | Direct invite (standard NIP-59 wrap) | [§7](#7-kind-3313--direct-invite) |

Retired kinds (`3300, 3301, 3304, 3305, 3307, 3311, 23308`) have no examples: their numbers are burned, never reused (CORD-02, Appendix B).

## 1. The envelope

Every durable plane event is the same three-layer shape (CORD-01): a kind `1059` **wrap** signed by the plane's derived stream key, containing a **seal** signed by the author's real key, containing the unsigned **rumor** that carries the functional kind. Sections 2–5 show only rumors; each rides inside this envelope at its plane's address.

### 1.1 Kind 1059 — the wrap, encrypted seal

Chat, Guestbook, rekey, and access planes, a restricted Channel's writer addresses included, use the **encrypted seal** (kind `20013`): the rumor is NIP-44-encrypted *again* inside the already-encrypted wrap, so it can never be lifted out as a standalone public event (CORD-02 §5).

Because the wrap reverses NIP-59 (fixed author, ephemeral `p`), delivery depends on relays **not** enforcing NIP-59's optional `p`-tag guard ("relays SHOULD only serve kind 1059 events intended for the marked recipient"): members subscribe by the stream author, and nobody is the random `p`. Communities must choose relays accordingly.

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
    ["p", "<random ephemeral pubkey>"]            // ephemeral "p", fixed author — NIP-59 reversed (CORD-01).
                                                  // Keep this key's secret if you want to NIP-09-delete the wrap later (CORD-01).
  ],
  "created_at": 1686840217,
  "sig": "<stream key signature>"
}
```

### 1.2 Kind 20014 — the plaintext seal

The Control Plane **only** (CORD-02 §5). Same wrap, but the seal's `content` holds the rumor's serialized JSON string rather than ciphertext (byte-verbatim, CORD-01), so a compaction can re-wrap the signed edition into a new epoch with the signature intact (CORD-06). See §4 for the full Control edition example inside this seal.

```jsonc
{
  "kind": 1059,
  "pubkey": "<control_pk>",                       // the control_root-derived signer: only staff can mint this wrap (CORD-02 §5)
  "content": nip44_encrypt(control_conv_key, {    // the community_root-derived read key: every member decrypts (CORD-02 §5)
    "id": "<seal id>",
    "kind": 20014,                                // plaintext seal
    "pubkey": "<actor's real pubkey>",
    "content": json_stringify({ /* the kind 3308 rumor, §4 */ }),  // the rumor's serialized JSON string, not a ciphertext
    "tags": [],
    "created_at": 1686840217,
    "sig": "<actor's real signature>"
  }),
  "tags": [ ["p", "<random ephemeral pubkey>"] ],
  "created_at": 1686840217,
  "sig": "<control signer signature>"
}
```

### 1.3 Kind 21059 — the ephemeral wrap

Identical structure to `1059`, but relays MUST NOT store it: broadcast to live subscribers and gone. It carries the Chat Plane's three realtime signals: the typing indicator (§2.7), voice presence (§2.8) and voice directives (§2.10).

```jsonc
{
  "kind": 21059,
  "pubkey": "<channel_pk>",                       // typing on a restricted Channel rides its writer address instead (§2.11)
  "content": nip44_encrypt(conv_key, { /* kind 20013 seal around a kind 23311, 23313 or 23314 rumor, §2.7, §2.8, §2.10 */ }),
  "tags": [ ["p", "<random ephemeral pubkey>"] ],
  "created_at": 1686840217,
  "sig": "<channel stream signature>"
}
```

## 2. Chat Plane rumors

All Chat rumors ride an encrypted seal (§1.1) at the Channel's address, and MUST commit `["channel", <channel_id>]` and `["epoch", <n>]` inside the author-signed rumor; a receiver checks both against the key that opened the wrap and drops a mismatch (CORD-03 §3). On a restricted Channel, posts ride a writer address instead (§2.11).

When the Community's disappearing-messages timer is set (CORD-08), every durable Chat rumor **and its outer wrap** also carry NIP-40 `["expiration", "<created_at + timer>"]` — except deletes (§2.4) and timer notices (§2.9), which never expire. The examples below omit the tag.

### 2.1 Kind 9 — Message

NIP-C7 shape: the `content` is the message text. (Not NIP-29, whose messages require an `h` tag and whose kind 9 definition has since been dropped; the registry assigns kind 9 to NIP-C7.)

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

An **inline quote** embeds another message in the timeline with a `q` tag (NIP-C7), citing the quoted message's *rumor* id (never the outer wrap's, which differs per re-wrap). It stays a kind 9 and renders as an ordinary timeline row that happens to carry a quoted card:

```jsonc
{
  "kind": 9,
  "pubkey": "<author>",
  "content": "Welcome!",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "902"],
    ["q", "<quoted message rumor id>", "", "<quoted author>"]
  ],
  "created_at": 1686840304
}
```

A **Role mention** names the Role in the text as `@` and its name, with a `["role", "<role_id>"]` tag beside it, at most 16 to a message (CORD-03 §3), so a client that doesn't know the tag still reads who was meant. Holders are notified when the Role is `mentionable`, or when the author holds MENTION_EVERYONE in the Channel; otherwise it renders as plain text, and a tag counts only beside text naming its Role (CORD-04 §8):

```jsonc
{
  "kind": 9,
  "pubkey": "<author>",
  "content": "@Moderators the spam is back",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["role", "<role_id hex>"],                    // the vsk 13 Role the text names
    ["ms", "318"]
  ],
  "created_at": 1686840400
}
```

### 2.2 Kind 1111 — Threaded reply

A **threaded reply** is a distinct action from an inline quote: it lives in a thread hanging off its root, not as a top-level timeline row. It is a NIP-22 comment (kind `1111`), not a kind 9 — reusing `q` for this would conflate "quote this inline" with "reply in a thread". Uppercase `K`/`E`/`P` pin the immutable *thread root*; lowercase `k`/`e`/`p` pin the *immediate parent*. All ids are *rumor* ids (never the outer wrap's). When the parent is itself a reply, its uppercase root tags are inherited verbatim, so the root stays stable at any nesting depth:

```jsonc
{
  "kind": 1111,
  "pubkey": "<author>",
  "content": "Replying in the thread!",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "744"],
    ["K", "9"],
    ["E", "<thread root rumor id>", "", "<root author>"],
    ["P", "<root author>"],
    ["k", "9"],
    ["e", "<immediate parent rumor id>", "", "<parent author>"],
    ["p", "<parent author>"]
  ],
  "created_at": 1686840360
}
```

Reactions, edits, and deletes target a threaded reply exactly as they target a kind-9 message (by its rumor id); the `k` tag they carry names the target's kind (`1111` for a reply, `9` for a message).

### 2.3 Kind 7 — Reaction

NIP-25 shape: `content` is the reaction (`"+"`, an emoji, …), tags name the reacted-to message, its author, and its kind.

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
    ["p", "<message author>"],
    ["k", "9"]
  ],
  "created_at": 1686840350
}
```

### 2.4 Kind 5 — Delete

NIP-09 shape: `e` tags name the author's own rumors to delete, `k` their kind, `content` an optional reason. A member's delete of their own past message is honored always — even after Dissolution (CORD-02 §9).

Note this delete names a *rumor* id relays never saw, so it is semantic **within the plane only** — members stop rendering the message, but the wrap ciphertext stays on relays. Scrubbing the ciphertext itself is a separate, best-effort NIP-09 delete of the wrap by its `p` tag (CORD-01), possible only if the publishing client kept the ephemeral key.

```jsonc
{
  "kind": 5,
  "pubkey": "<author>",
  "content": "",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "533"],
    ["e", "<own message rumor id>"],
    ["k", "9"]
  ],
  "created_at": 1686841000
}
```

### 2.5 Kind 3302 — Edit

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

### 2.6 Kind 3310 — WebXDC peer signal

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

### 2.7 Kind 23311 — Typing indicator

An **ephemeral** action: same seal-and-rumor shape at the same Channel address, but the outer wrap is kind `21059` (§1.3) and the rumor kind is ephemeral-range too, so relays never store any layer of it. Presence of the event is the signal; the rumor carries nothing.

```jsonc
{
  "kind": 23311,
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

### 2.8 Kind 23313 — Voice presence

Ephemeral like the typing indicator (`21059` wrap, §1.3): call heartbeats are realtime-only, nothing worth storing. The `content` is the verb; a `joined` repeats every 30 seconds and goes stale after 90 (three missed heartbeats), and a `left` carries only the binding (CORD-07 §4). What a `joined` names is its transport: a brokered call (CORD-07 §2) names the broker-assigned SFU `identity` and the `broker` origin; a peer-to-peer call (CORD-07 §8) names `["transport", "iroh"]`, the member's iroh `endpoint` and the `relay` it's reached through, and no identity or broker. A client shows a member on a transport it doesn't speak as in the call elsewhere, never drops them.

Either kind of `joined` MAY carry `["muted"]` and `["deafened"]` (deafened implies muted), `["video", "screen"]` while its author shares their screen and `["video", "camera"]` while their camera is on, re-sent the moment one changes. Presence stays at the Channel's read address even on a restricted Channel: being in a call is CONNECT, not posting (CORD-03 §1).

```jsonc
// Joined, brokered (also the heartbeat)
{
  "kind": 23313,
  "pubkey": "<member>",
  "content": "joined",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["identity", "<SFU identity>"],
    ["broker", "https://broker.example"],
    ["ms", "417"]
  ],
  "created_at": 1686840217
}

// Joined, peer-to-peer: a fresh endpoint per join, dialled only through a relay the dialler trusts
{
  "kind": 23313,
  "pubkey": "<member>",
  "content": "joined",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["transport", "iroh"],
    ["endpoint", "<iroh EndpointId hex>"],         // 64 lowercase hex; the QUIC handshake proves the peer holds it
    ["relay", "https://relay.example/"],          // the iroh relay that endpoint is reached through; names no IP address
    ["muted"],                                    // optional flags, sent while true
    ["deafened"],
    ["video", "screen"],
    ["video", "camera"],
    ["ms", "650"]
  ],
  "created_at": 1686840240
}

// Left (best-effort; a missed one heals by staleness), the same on either transport
{
  "kind": 23313,
  "pubkey": "<member>",
  "content": "left",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "902"]
  ],
  "created_at": 1686840305
}
```

### 2.9 Kind 1740 — Timer notice

Posted by staff after changing the Community's disappearing-messages timer (CORD-08 §4), one per Channel whose key they hold — the same kind and `timer` tag NIP-17 disappearing-DM clients use. Rendered as an inline notice row; displayed only if the author holds `MANAGE_METADATA` in the fold. Never carries an `expiration` tag itself.

```jsonc
{
  "kind": 1740,
  "pubkey": "<staff member>",
  "content": "",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["ms", "233"],
    ["timer", "2592000"]                          // the new timer in seconds; "0" = turned off
  ],
  "created_at": 1686845000
}
```

### 2.10 Kind 23314 — Voice directive

A moderator's order in a call (CORD-07 §7), ephemeral like presence (`21059` wrap, §1.3) and at the read address like it. Signed by a member holding MUTE_MEMBERS, DEAFEN_MEMBERS or MOVE_MEMBERS, as the verb needs, who strictly outranks the target, citing their Grant (`vac`, absent when the owner acts). `do` is one of `mute`, `unmute`, `deafen`, `undeafen`, `move`, `disconnect`; a `move` names its destination in `to`. Every receiver honors it while the target stays in the call; per target, the newest of each pair (mute and unmute, deafen and undeafen) by millisecond time decides, and a tie keeps them muted or deafened. Since nothing stores it, the moderator's client re-asserts its standing directives whenever the target rejoins.

```jsonc
// Mute
{
  "kind": 23314,
  "pubkey": "<moderator>",
  "content": "",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["p", "<target pubkey>"],
    ["do", "mute"],
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"],
    ["ms", "512"]
  ],
  "created_at": 1686840500
}

// Move: the target is asked to leave for another Channel's call
{
  "kind": 23314,
  "pubkey": "<moderator>",
  "content": "",
  "tags": [
    ["channel", "<channel_id>"],
    ["epoch", "0"],
    ["p", "<target pubkey>"],
    ["do", "move"],
    ["to", "<destination channel_id>"],           // move only
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"],
    ["ms", "77"]
  ],
  "created_at": 1686840560
}
```

### 2.11 Restricted Channels — posting at a writer address

A Channel whose `@everyone` lacks SEND_MESSAGES there is **restricted** (CORD-03 §1). Reading is unchanged, but posting takes a **writer key** only its writers hold: the wrap's author is the writer address, `group_key("concord/channel-writer", writer_secret, channel_id, writer_epoch).pk`, its sk signs the wrap, and the content is still encrypted under the Channel's read key. The Writers ledger (§4, vsk 18) says which address takes posts when, and the writer secret arrives as a delivery (§5.2).

Inside, the rumor commits `["wepoch", "<n>"]`, checked strict-equal against the writer epoch whose address served it (a `wepoch` at the read address is dropped), and carries its author's writer certificate as `["wcert", "<signature hex>"]` (§5.3; the first `wcert` counts, and a malformed one is none). Everything moves except reactions, deletions, voice presence and voice directives, which stay at the read address; typing moves too, so only a writer shows as typing.

```jsonc
{
  "kind": 1059,
  "pubkey": "<writer_pk>",                        // the live writer address, not channel_pk
  "content": nip44_encrypt(conv_key, {            // conv_key = the Channel's read key, as at the read address
    "kind": 20013,
    "pubkey": "<author's real pubkey>",
    "content": nip44_encrypt(conv_key, {
      "id": "<rumor id>",
      "kind": 9,
      "pubkey": "<author's real pubkey>",
      "content": "v0.5.0 is out!",
      "tags": [
        ["channel", "<channel_id>"],
        ["epoch", "0"],                           // the read key's epoch, as on any Chat rumor
        ["ms", "640"],
        ["wepoch", "3"],                          // the writer epoch whose address serves it
        ["wcert", "<writer certificate: 64-byte signature hex>"]
      ],
      "created_at": 1722500300
    }),
    "tags": [],
    "created_at": 1722500300,
    "sig": "<author's real signature>"
  }),
  "tags": [ ["p", "<random ephemeral pubkey>"] ],
  "created_at": 1722500300,
  "sig": "<writer key signature>"
}
```

A post that the ledger, Roster and memberlist don't stand behind is **held** rather than shown: kept apart from history, judged again whenever any of them moves, and flagged only to the Channel's managers (CORD-03 §1).

## 3. Guestbook Plane rumors

Encrypted seals (§1.1) at `guestbook_pk` (CORD-02 §5). The Guestbook coalesces flat — one final state per npub, latest wins by millisecond time, ties broken by the lower rumor id. Timeouts (§3.4) coalesce the same way, apart from membership: they silence a member without changing who is one.

### 3.1 Kind 3306 — Join / Leave

Self-signed; the `content` is the verb. A Join MAY carry invite attribution echoed from the bundle (CORD-05 §1).

```jsonc
// Join, with optional invite attribution
{
  "kind": 3306,
  "pubkey": "<member>",
  "content": "join",
  "tags": [
    ["invite", "<creator pubkey>", "Reddit"],     // optional, Joins only
    ["ms", "128"]
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
    ["p", "<target pubkey>"],
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"],
    ["ms", "301"]
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

### 3.4 Kind 3314 — Timeout

Signed by a member holding `MODERATE_MEMBERS` server-wide (never through a Channel's overwrite) who strictly outranks the target, citing their Grant in `vac` (absent when the owner acts; CORD-04 §8). `until` is unix seconds, at most 28 days past the rumor's own time; one further out reads as exactly that. While it runs, readers collapse the target's posts dated or edited inside the window, their client stops offering composition, edits and reactions, and calls treat them as unable to speak. Per target, the newest Timeout by millisecond time decides, the lower rumor id breaking a tie, among those whose signers the Roster lets time the target out.

```jsonc
// Timeout: silences the target for an hour
{
  "kind": 3314,
  "pubkey": "<moderator>",
  "content": "",
  "tags": [
    ["p", "<target pubkey>"],
    ["until", "1722413600"],                      // unix seconds
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"],
    ["ms", "455"]
  ],
  "created_at": 1722410000
}

// Lift: a later Timeout whose until is already past
{
  "kind": 3314,
  "pubkey": "<moderator>",
  "content": "",
  "tags": [
    ["p", "<target pubkey>"],
    ["until", "0"],
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"],
    ["ms", "88"]
  ],
  "created_at": 1722411000
}
```

A Refounding starts a fresh Guestbook, so its Refounder re-issues in its own name each running Timeout it could issue itself, dated as first issued; the rest lapse for anyone reading only the new epoch.

## 4. Control Plane — kind 3308 editions

Every authority action is a kind `3308` **edition** rumor inside a **plaintext seal** (§1.2) at `control_pk` — the staff-held signer's address (CORD-02 §5): every member subscribes, verifies, and reads it, but only a `control_root` holder can publish to it. The tags carry the edition machinery (CORD-04 §1); the `content` is the entity's new state as JSON, its structure selected by `vsk`.

The common frame:

```jsonc
{
  "kind": 3308,
  "pubkey": "<actor's real pubkey>",
  "content": "<the entity's new state, per-vsk below, as a JSON string>",
  "tags": [
    ["vsk", "3"],                                 // entity type (registry below)
    ["eid", "<entity id, 32-byte hex>"],          // the stable coordinate
    ["ev",  "4"],                                 // this edition's version, climbs from 1
    ["ep",  "<prev edition hash>"],               // chain link, absent on the first edition
    ["vac", "<grant eid>", "<grant version>", "<grant edition hash>"],  // absent when the owner acts
    ["eh",  "2"],                                 // marked: the hash covers the signer (CORD-04 §1)
    ["eb",  "<edition_binding(community_id) hex>"]  // marked: bound to this Community (CORD-02 A.6)
  ],
  "created_at": 1686840217
}
```

The last two tags **mark** the edition (CORD-04 §1). Every edition in a Community on Roles v2 (one whose owner has published `@everyone`, vsk 13) carries them, and so does every vsk 13 to 18 edition in any Community. A marked edition's hash also covers its signer's key, so the next edition's `ep` names who signed as well as what. A reader refuses a marked edition bound to another Community, an `eh` other than `"2"`, and an unmarked edition of vsk 13 to 18.

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
  "message_expiration": 2592000,
  "voice_relays": ["https://iroh.example.com/"],  // optional: the iroh relays its peer-to-peer calls use, ≤ 8 https URLs (CORD-07 §8)
  "custom": { "rules": "Be excellent to each other." }
}
```

### vsk 1 — Role, legacy (CORD-04 §2)

The Roster Communities kept before Roles v2: Roles ordered by a `u32` `position`, optionally scoped to one Channel. Read until a Community activates vsk 13; from then on vsk 1 is history, still linking the chain a carried Role continues, standing for nothing. `eid` = the `role_id`, random 32 bytes minted at creation. Gated by `MANAGE_ROLES`.

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

`eid` = the `channel_id`. Gated by `MANAGE_CHANNELS`. Every Channel is callable (CORD-07); there is no per-Channel voice flag.

```jsonc
{ "name": "general", "private": false }
{ "name": "lounge",  "private": false }
```

Four optional protocol fields, round-tripped by every editor:

```jsonc
{ "name": "announcements", "private": false,
  "position": "M",                                // rank key (CORD-04 §3's alphabet): lower sorts first
  "category": "<category_id hex>",                // the Category it files under (vsk 15); absent = uncategorized
  "topic": "Release notes" }                      // ≤ 1024 bytes
{ "name": "lounge", "private": false, "position": "N",
  "view": "voice" }                               // "chat" (the default), "forum" or "voice"; an unknown view reads as "chat"
```

A Channel an older client marked voice, read as `"view": "voice"` while `view` is absent (CORD-03 §2):

```jsonc
{ "name": "lounge", "private": false, "voice": true }
```

A deletion is an edition setting the terminal flag, terminal over the whole chain:

```jsonc
{ "name": "general", "private": false, "deleted": true }
```

On Roles v2 a **Private Channel seals its metadata** under the Channel's key, leaving plain only what every member needs to resolve access (CORD-03 §2); a Community still on the legacy Roster keeps it plain. Only a key holder can write it; the Rotator re-seals it under the new key after a rekey (CORD-06 §3).

```jsonc
{ "private": true,
  "epoch": "4",                                   // decimal string: the channel_epoch the seal is under
  "sealed": nip44_encrypt(channel_conv_key, {     // the Channel's group key at that epoch, self-ECDH (CORD-01)
    "name": "staff",
    "topic": "Mods only",
    "position": "B",
    "category": "<category_id hex>",
    "creator": "<creator pubkey>",                // optional: let in while they hold MANAGE_CHANNELS (CORD-04 §8)
    "prev": "<this edition's ep hex>"             // null on a first edition; a seal naming another prev reads as unreadable
  }) }
```

A born-private Channel's first edition, at `channel_epoch` 1, its key already delivered by a Channel rotation (CORD-03 §2):

```jsonc
{ "epoch": "1", "private": true, "sealed": nip44_encrypt(channel_conv_key, { "creator": "<creator pubkey>", "name": "staff", "prev": null }) }
```

Deleting a Private Channel takes only the bit, never the key: the head's sealed content republished verbatim beside the terminal flag, exempt from the `prev` check:

```jsonc
{ "private": true, "epoch": "4", "sealed": "<the head's sealed string, verbatim>", "deleted": true }
```

### vsk 3 — Grant (CORD-04 §2)

`eid` = `grant_locator(community_id, member)` (CORD-02 A.6). Honored only if the signer outranks every Role handed out; empty `role_ids` is a revoke. A staff-making Grant also delivers the Control Plane write secret in `control_wrap` (CORD-04 §3): NIP-44 ciphertext under the granter↔member pairwise key, its plaintext the fixed-width 40 bytes `epoch_be[8] ‖ control_root[32]`, adopted only if the secret derives to the recipient's held `control_pk` at that epoch. Every other reader treats it as opaque bytes.

```jsonc
{
  "member": "<member pubkey>",
  "role_ids": ["<role_id hex>", "<role_id hex>"],
  "control_wrap": "<base64>"                      // optional: staff write key delivery (CORD-04 §3)
}
```

### vsk 4 — Banlist (CORD-04 §4)

`eid` = `banlist_locator(community_id)` (CORD-02 A.6). The whole list, replaced entire on every edit; signer must hold `BAN`.

```jsonc
["<banned pubkey>", "<banned pubkey>"]
```

### vsk 8 — Invite-link registry (CORD-05 §5)

`eid` = `invite_links_locator(community_id, creator)` (CORD-02 A.6). Locators only, never tokens or URLs; honored while its author holds `CREATE_INVITE`.

```jsonc
["<link_signer pubkey hex>", "<link_signer pubkey hex>"]
```

### vsk 11 — Pin List (CORD-04 §7)

`eid` = `pins_locator(community_id, channel_id)` (CORD-02 A.6). One list per Channel, replaced entire on every edit; signer must hold `PIN_MESSAGES`. Each entry carries the pinned message's original seal verbatim plus its one-shot NIP-44 message keys, so any reader able to open the list's form — including one holding no historical keys — verifies author, words, and time from the pin alone.

```jsonc
// Public Channel: plaintext — the plane's wrap is the gate, and compaction
// re-wrapping it to each new root keeps it readable forever.
{ "entries": [
    { "seal": { /* the original kind-20013 seal event, byte-verbatim */ },
      "keys": "<76 bytes hex: chacha_key[32] || chacha_nonce[12] || hmac_key[32]>",
      "wrap": "<hex event id>",    // optional: jump-to-context locator
      "edit": {                    // optional: the author's own Edit (kind 3302),
        "seal": { /* … */ },       // proven the same way, so a keyless reader
        "keys": "<76 bytes hex>"   // never reads superseded words as current
      } }
] }
```

```jsonc
// Private Channel: the same list, NIP-44-sealed under the Channel's group key
// at the named epoch (self-ECDH conversation key, CORD-01).
{ "epoch": "4", "sealed": nip44_encrypt(channel_conv_key, { "entries": [ … ] }) }
```

Caps: 25 entries and 32,768 bytes of `content`, judged on the carried bytes — a violating edition still folds and chains, but reads as an empty list (CORD-04 §7). An entry failing verification (seal kind, signature, MAC, decryption, unpad/parse, rumor kind, author equality, or the rumor's `channel` tag not matching this list's Channel) is dropped alone; an `edit` bundle failing the same checks — with kind `3302`, and additionally the Edit's author matching the original's and its `e` tag naming the original — costs only the revision, never the pin. A member's deletion of their own message kills its pin.

### vsk 13 — Role and `@everyone` (CORD-04 §2)

`eid` = the `role_id`, random 32 bytes minted at creation. Gated by `MANAGE_ROLES`: the signer's Roles ranked strictly above both the rank it claims and the rank it replaces must hold every bit it carries (the owner is exempt). A Community folds at most 100 live Roles, the lowest `role_id`s.

```jsonc
{
  "role_id": "<role_id hex>",
  "name": "Moderators",                           // ≤ 64 bytes
  "rank": "M",                                    // rank key: 1–32 bytes of 0-9A-Za-z, never ending in "0"; lower outranks
  "permissions": "67108904",                      // decimal string: 1<<3 KICK | 1<<5 MANAGE_MESSAGES | 1<<26 MODERATE_MEMBERS
  "color": 15158332,                              // cosmetic badge tint, 0 = theme default
  "display": true,                                // optional: holders list under this Role's own heading
  "mentionable": true                             // optional: any member may @mention it (§2.1)
}
```

A deletion is terminal: it leaves every holder at once, frees the slot, and the `role_id` is never reused.

```jsonc
{ "deleted": true, "role_id": "<role_id hex>" }
```

**`@everyone`** sits at `eid` = `everyone_locator(community_id)` (CORD-02 A.6): what every member holds before any Role, beneath every Role, never deleted. The owner's first edition here moves the Community onto Roles v2.

```jsonc
{
  "permissions": "4186112",                       // the switching defaults: 1<<13 VIEW_CHANNEL through 1<<21 VIDEO
  "legacy": ["<channel_id hex>", "<channel_id hex>"]  // the Channels that stood at the switch, ≤ 256, carried by every later edition
}
```

### vsk 14 — ACL overwrite (CORD-04 §8)

One overwrite per (scope, target): `eid` = `acl_locator(community_id, scope, kind, target)` (CORD-02 A.6), the scope a Channel's or a Category's id. An overwrite touches only `MANAGE_MESSAGES` and the channel permissions, bits 13 to 26 (the mask `134209568`); a reader clears any other bit as it parses. Gated by `MANAGE_ROLES`, judged by downward support: the signer's Roles ranked strictly above the target must hold `MANAGE_ROLES` and every bit it allows or denies.

```jsonc
// @everyone may read #announcements but not post there, which restricts it (§2.11)
{ "scope": "<channel_id hex>", "target": { "kind": "everyone" }, "allow": "0", "deny": "16384" }      // 1<<14 SEND_MESSAGES

// …and one Role may
{ "scope": "<channel_id hex>", "target": { "kind": "role", "id": "<role_id hex>" }, "allow": "16384", "deny": "0" }

// One member, on a Category: no reactions in any Channel synced to it
{ "scope": "<category_id hex>", "target": { "kind": "member", "id": "<member pubkey>" }, "allow": "0", "deny": "131072" }   // 1<<17 ADD_REACTIONS

// Let a Role into a Private Channel, and clear an overwrite (allowing and denying nothing)
{ "scope": "<channel_id hex>", "target": { "kind": "role", "id": "<role_id hex>" }, "allow": "8192", "deny": "0" }        // 1<<13 VIEW_CHANNEL
{ "scope": "<channel_id hex>", "target": { "kind": "everyone" }, "allow": "0", "deny": "0" }
```

### vsk 15 — Category (CORD-03 §4)

`eid` = the `category_id`, random 32 bytes minted at creation. Gated by `MANAGE_CHANNELS`. Moving a Channel into one is an edition on the Channel (vsk 2's `category`), never on the Category. A reader folds at most 100 Categories, the lowest `category_id`s not deleted.

```jsonc
{ "name": "Staff", "position": "B" }              // ≤ 64 bytes; position is a rank key ordering Categories among themselves
```

Deleting a Category unfiles its Channels, which render uncategorized, and leaves its overwrites in place, so a Channel synced to it keeps its rules:

```jsonc
{ "deleted": true }
```

### vsk 16 — Tenure (CORD-04 §9)

`eid` = `tenure_locator(community_id, member, sealer)` (CORD-02 A.6), one per member per **sealer**: the member who publishes it, in the same action that reduces the member's authority, so the decisions they made keep standing. A reader ignores a Tenure at a coordinate naming another sealer than its signer, and one its own member wrote. Each entry judges the listed editions as if their author still held `permissions` through a Role at `rank`; at most 16 entries and 512 heads.

```jsonc
{
  "member": "<member pubkey>",
  "sealed": [
    { "rank": "D",                                // the standing the member held just before the reduction
      "permissions": "2066",                      // 1<<1 MANAGE_CHANNELS | 1<<4 BAN | 1<<11 PIN_MESSAGES
      "heads": ["<edition hash>", "<edition hash>"] }   // the Control heads they authored that it keeps standing
  ]
}
```

### vsk 17 — Channel sync (CORD-04 §8)

`eid` = `sync_locator(community_id, channel_id)` (CORD-02 A.6). A synced Channel resolves against its Category's overwrites and ignores its own. A sync swaps every rule on both sides at once, so its signer must be able to write every overwrite in the Channel's scope, the Category's it syncs to, and the one it leaves.

```jsonc
{ "channel": "<channel_id hex>", "sync": "<category_id hex>" }
{ "channel": "<channel_id hex>" }                 // sync absent: the Channel's own overwrites again
```

### vsk 18 — Writers ledger (CORD-03 §1)

`eid` = `writers_locator(community_id, channel_id)` (CORD-02 A.6). Which address a restricted Channel's posts land at, when (§2.11). Gated by `MANAGE_CHANNELS`. Each edition appends exactly one entry to its predecessor's list, verbatim, dated within ten minutes of the edition's `created_at`. Entries run in order of `at` (unix ms), writer epochs strictly rising, at most 64; at the cap the oldest goes, and a writer entry moves to `retired` so its address and window still read.

```jsonc
{
  "channel": "<channel_id hex>",
  "ledger": [
    // … older entries
    { "at": 1722500000000, "epoch": 3, "writer": "<writer_pk hex>", "root": 2,
      "by": "<minter pubkey>", "certifier": "<certifier pubkey>" },   // restricted: posts move to writer epoch 3's address
    { "at": 1722600000000, "stop": "<writer pubkey>", "from": 1722550000000 },   // epoch 3's certificate for them vouches for nothing from "from" (optional, ≤ at)
    { "at": 1722700000000, "open": true }        // reopened: posts land at the read address again
  ],
  "retired": [                                    // optional: writer entries the cap dropped
    [1, "<writer_pk hex>", 1719800000000, 1720000000000, "<certifier pubkey>"],   // epoch, address, window from and to (ms), certifier
    [2, "<writer_pk hex>", 1720100000000, 1721000000000]                         // an epoch that named no certifier: four elements
  ]
}
```

A writer entry names the root epoch it was minted under (`root`), so a Refounding retires it, and its minter (`by`, the edition's signer). `at`, `epoch`, `root` and `from` are JSON numbers, writer epochs below 2^53.

### vsk 10 — Dissolved tombstone (CORD-02 §9)

Owner-signed, chainless, exempt from version discipline — published at `dissolved_pk`, not the Control Plane address. Presence of one valid owner-signed edition *is* the state.

The `eid` is the `community_id`, and a verifier MUST check it: `dissolved_pk` derives from that id with no secret, so the plane is public to read and to sign at, and a payload naming no Community would let an owner's tombstone for one be re-wrapped to kill another (CORD-02 §9).

```jsonc
{
  "kind": 3308,
  "pubkey": "<owner>",
  "content": "",
  "tags": [
    ["vsk", "10"],
    ["eid", "<community_id>"]   // binds the tombstone to the Community it kills
    // chainless: no ev, no ep, no vac
  ],
  "created_at": 1725000000
}
```

Remaining `vsk` values carry no edition: `5` and `12` are reserved, `6`/`9` are claimed by the addressable invite marker (§6.1), `7` is retired.

### 4.1 Byte-exact contents

Unlike the rest of this section, these are real values: the exact `content` bytes Vector writes, pinned by its test `contents_match_the_spec_vectors`. Inputs: Channel or overwrite scope `02`×32, `role_id` `05`×32, Category `06`×32, edition hashes `07`×32 and `08`×32, and members by secret key: member `531fe606…fe337` (secret `03`×32); in the ledger, writer `f76a39d0…dde6e` (`0a`×32), minter `552c630b…12a84` (`0b`×32), certifier `0f0fb9a2…2d177` (`0c`×32), epoch 1's retired address from `0d`×32 and its certifier from `0e`×32, and epoch 2's retired address from `0f`×32. CORD-02 A.6's table instead takes `03`×32 as the member's x-only bytes directly. A writer of another client may order keys differently; these are what a reader can byte-compare against Vector.

Role, its deletion, and `@everyone` with one legacy Channel (vsk 13):
```json
{"role_id":"0505050505050505050505050505050505050505050505050505050505050505","name":"Moderators","rank":"M","permissions":"67108904","color":15158332,"display":true,"mentionable":true}
{"deleted":true,"role_id":"0505050505050505050505050505050505050505050505050505050505050505"}
{"permissions":"4186112","legacy":["0202020202020202020202020202020202020202020202020202020202020202"]}
```
Grant (vsk 3) and Banlist (vsk 4):
```json
{"member":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","role_ids":["0505050505050505050505050505050505050505050505050505050505050505"]}
["531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"]
```
Overwrites (vsk 14): `@everyone` denied SEND_MESSAGES, a Role allowed it, a member denied ADD_REACTIONS:
```json
{"scope":"0202020202020202020202020202020202020202020202020202020202020202","target":{"kind":"everyone"},"allow":"0","deny":"16384"}
{"scope":"0202020202020202020202020202020202020202020202020202020202020202","target":{"kind":"role","id":"0505050505050505050505050505050505050505050505050505050505050505"},"allow":"16384","deny":"0"}
{"scope":"0202020202020202020202020202020202020202020202020202020202020202","target":{"kind":"member","id":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"},"allow":"0","deny":"131072"}
```
Sync and unsync (vsk 17):
```json
{"channel":"0202020202020202020202020202020202020202020202020202020202020202","sync":"0606060606060606060606060606060606060606060606060606060606060606"}
{"channel":"0202020202020202020202020202020202020202020202020202020202020202"}
```
Tenure (vsk 16):
```json
{"member":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","sealed":[{"rank":"D","permissions":"2066","heads":["0707070707070707070707070707070707070707070707070707070707070707","0808080808080808080808080808080808080808080808080808080808080808"]}]}
```
Channels (vsk 2): plain, with every optional field Vector moves, a voice Channel, and a deletion:
```json
{"name":"general","private":false}
{"name":"announcements","private":false,"category":"0606060606060606060606060606060606060606060606060606060606060606","position":"M","topic":"Release notes"}
{"name":"lounge","private":false,"position":"N","view":"voice"}
{"name":"general","private":false,"deleted":true}
```
Category and its deletion (vsk 15):
```json
{"name":"Staff","position":"B"}
{"deleted":true}
```
Writers ledger (vsk 18), a writer entry, a stop recording a departure, a reopen, and two retired windows:
```json
{"channel":"0202020202020202020202020202020202020202020202020202020202020202","ledger":[{"at":1722500000000,"by":"552c630b64b54bf50210c9e253d38bd4949c72e22873500f6285c2bede312a84","certifier":"0f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177","epoch":3,"root":2,"writer":"f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e"},{"at":1722600000000,"from":1722550000000,"stop":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"},{"at":1722700000000,"open":true}],"retired":[[1,"2f1b310f4c065331bc0d79ba4661bb9822d67d7c4a1b0a1892e1fd0cd23aa68d",1719800000000,1720000000000,"99c2aa85d2b21a62f396907a802a58e521dafd5bddaccbd72786eea189bc4dc9"],[2,"1a7a569e91dbf60581509c7fc946d1003b60c7dee85299538db6353538d59574",1720100000000,1721000000000]]}
```

## 5. Rekeys — kind 3303

A kind `3303` either **rotates** a key, removing whoever it leaves out (§5.1), or **delivers** keys to members owed them, removing nobody (§5.2). Both are wrapped and encrypted-sealed like any stream event, and the seal's npub is the actor, whose authority a receiver verifies before accepting anything.

### 5.1 Rotations

Delivered at a **rekey address** derived from the *prior* secret (CORD-06 §2). The seal's npub is the Rotator.

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

Each `wrapped` plaintext is fixed-width per form (CORD-06 §1): a Channel rotation's is 72 bytes — `scope_id[32] ‖ epoch_be[8] ‖ new_key[32]` — while a base rotation's appends the next epoch's Control Plane keys, 104 bytes for a member (`… ‖ new_control_pk[32]`) and 136 for a staff recipient (`… ‖ new_control_root[32]`). All are NIP-44-encrypted under the Rotator↔recipient pairwise key; the recipient finds their blob by computing their `locator` (CORD-06 §2) and verifies the inner scope and epoch against the tags before accepting the key — a staff recipient also that the delivered secret derives to the delivered pubkey. A 72-byte *base* blob marks a legacy, pre-split rotation (CORD-06 §3): honored when reading old epochs — its acceptor folds that epoch's Control at the legacy address — never minted by a compliant Rotator.

A base rotation (a Refounding) names the all-zero scope and cites the Grant its Rotator acts under, like any authority action (CORD-06 §3, Authority). Marked **Severing** with `["sever", "1"]` on every chunk, it asks each member adopting it to tombstone the public invite links they created under an older epoch and never refresh them into the new one, closing the door the removed party came in by (CORD-06 §3). `"1"` is its only value, and a receiver that reads it on any chunk applies it to the whole rotation:

```jsonc
{
  "kind": 3303,
  "pubkey": "<rotator's real pubkey>",
  "content": "[ {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"}, {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"} ]",
  "tags": [
    ["scope",      "0000000000000000000000000000000000000000000000000000000000000000"],   // the community_root
    ["newepoch",   "3"],
    ["prevepoch",  "2"],
    ["prevcommit", "<epoch-key commitment hex, CORD-02 A.5>"],
    ["chunk",      "2", "2"],
    ["vac",        "<grant eid>", "<grant version>", "<grant edition hash>"],   // absent when the owner rotates
    ["sever",      "1"]                           // optional, base rotations only; meaningless on a Channel scope
  ],
  "created_at": 1722500000
}
```

### 5.2 Deliveries

A 3303 carrying `["delivery", "<form>"]` hands keys to members who are owed them (CORD-03 §5, CORD-06 §1) and is never a rotation: it advances no epoch, and nothing it omits removes anyone. Deliveries ride a Channel's **access plane**, `group_key("concord/channel-access", community_root, channel_id, root_epoch)`, under an encrypted seal, their content the same blob array, with no `prevepoch`, `prevcommit` or `chunk`. Each blob's `locator` is computed as a rotation's (CORD-06 §2), from the deliverer and recipient at the delivery's scope and epoch, so anyone can see who is already served. A delivery carries at most 80 blobs, 60 of the 104-byte history form and 48 when it hands out certificates; a reader accepts up to 120, and treats a `delivery` form or blob width it doesn't understand as no removal verdict.

An **access** delivery of a Private Channel's current key, its blob the 72-byte Channel form, `channel_id[32] ‖ epoch_be[8] ‖ channel_key[32]`:

```jsonc
{
  "kind": 3303,
  "pubkey": "<deliverer's real pubkey>",
  "content": "[ {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"} ]",
  "tags": [
    ["scope",    "<channel_id hex>"],
    ["newepoch", "4"],                            // the Channel's current epoch: the key it delivers
    ["delivery", "access"]
  ],
  "created_at": 1722500000
}
```

A **writer** delivery of a restricted Channel's writer secret (§2.11), to each member who may post there and each `MANAGE_CHANNELS` holder. Writer secrets travel as form `access`, their scope telling them apart, and the blob is 72 bytes in the Channel shape, `writer_scope[32] ‖ writer_epoch_be[8] ‖ writer_secret[32]`. A member adopts the secret only if it derives to the address the ledger names for that epoch:

```jsonc
{
  "kind": 3303,
  "pubkey": "<minter's real pubkey>",
  "content": "[ {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"}, {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"} ]",
  "tags": [
    ["scope",    "<writer scope hex>"],           // sha256("concord/writer-scope" ‖ channel_id)
    ["newepoch", "3"],                            // the writer epoch
    ["delivery", "access"],
    ["writer",   "<writer_pk hex>"],              // the address the delivered secret derives to
    ["cert",     "<recipient pubkey>", "<writer certificate hex>"],   // one per recipient handed a certificate (§5.3)
    ["cert",     "<recipient pubkey>", "<writer certificate hex>"],
    ["mint",     "1", "2"]                        // part 1 of 2 of the epoch's minting delivery; absent on any later serving
  ],
  "created_at": 1722500000
}
```

A **certifier** delivery hands the writer epoch's certifier secret to each `MANAGE_CHANNELS` holder, so any manager can certify a writer the Channel gains without minting a new epoch:

```jsonc
{
  "kind": 3303,
  "pubkey": "<minter's real pubkey>",
  "content": "[ {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"} ]",
  "tags": [
    ["scope",    "<certifier scope hex>"],        // sha256("concord/certifier-scope" ‖ channel_id)
    ["newepoch", "3"],
    ["delivery", "access"],
    ["writer",   "<certifier pubkey>"]            // the certifier the delivered secret derives to
  ],
  "created_at": 1722500000
}
```

A **history** delivery hands a member holding READ_MESSAGE_HISTORY an earlier epoch, read-only: its Chat Plane address and conversation key, never the secret, so they can read that epoch but never sign into it. Each event carries one epoch, each blob 104 bytes, `history_scope[32] ‖ epoch_be[8] ‖ address[32] ‖ conv_key[32]`:

```jsonc
{
  "kind": 3303,
  "pubkey": "<deliverer's real pubkey>",
  "content": "[ {\"locator\": \"<hex>\", \"wrapped\": \"<base64>\"} ]",
  "tags": [
    ["scope",    "<history scope hex>"],          // sha256("concord/history-scope" ‖ channel_id)
    ["newepoch", "2"],                            // the earlier epoch it opens
    ["delivery", "history"]
  ],
  "created_at": 1722500000
}
```

### 5.3 Kind 3320 — Writer certificate preimage

Never published. A writer certificate is the certifier's BIP-340 signature over this event's id, and rides as `["cert", <recipient>, <signature>]` on a writer delivery and `["wcert", <signature>]` on each post (CORD-03 §1). The digest is `sha256("concord/writer-cert" ‖ community_id ‖ channel_id ‖ epoch_be[8] ‖ writer_xonly)`, so one certificate vouches for one member, at one writer epoch, in one Channel.

Unlike the rest of this file, these are real values: CORD-03 §1's test vector, for `community_id` `01`×32, `channel_id` `02`×32, writer epoch `3`, writer `04`×32 and certifier secret `05`×32.

```jsonc
{
  "id": "1b6fcc32de4a485d7b0109b0e5dd91b7c676fcb26f7dc41c8c2bdc7e3f2cbe90",
  "kind": 3320,
  "pubkey": "62c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7",   // the certifier
  "content": "",
  "tags": [
    ["digest", "f49b5c7359b09366b5b96e074d2b7c5a84bd714a04bf0e6270d13c02d453e619"]
  ],
  "created_at": 0,
  "sig": "cd1c3030e1220c539f1efb50d32e5b83432baa20eaa8709aa935050dc11a6ac6e25c3f9555b729cee65829fdbf1ba5e7656865a4fca860e42b05c8341922895a"
  // the certificate. Signing again needn't reproduce it: any signature that verifies is the certificate.
}
```

## 6. Outside the wrap

Three kinds relays see bare, signed by ordinary (or per-link) keys.

### 6.1 Kind 33301 — public invite bundle (CORD-05 §2)

Addressable, authored by the link's dedicated `link_signer` keypair with an empty `d` identifier — the coordinate `(33301, link_signer, "")` is exactly what the link's naddr names. The `vsk` tag marks it live (`6`) or a revocation tombstone (`9`).

The guard is the coordinate itself: a squatter's event is a different author, hence a different coordinate, and never matches the fetcher's filter. Since the `link_signer` secret lives only in the creator's Invite List (CORD-05 §4), a link-holder can preview and join but can never re-post, replace, or tombstone the bundle. And a hostile bundle can't smuggle a false owner regardless — the `community_id` self-certifies (CORD-05 §1).

```jsonc
// live bundle
{
  "kind": 33301,
  "pubkey": "<link_signer pubkey>",
  "content": "<nip44_encrypt(bundle_key, bundle)>",
  "tags": [
    ["d", ""],
    ["vsk", "6"]
  ],
  "created_at": 1719800000,
  "sig": "<link_signer signature>"
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
  "control_pk": "<hex>",                          // the Control Plane signer's pubkey at that epoch (CORD-02 §5)
  "channels": [
    { "id": "<channel_id>", "key": "<hex>", "epoch": 1, "name": "testers" }
  ],
  "relays": ["wss://jskitty.com/nostr", "wss://relay.ditto.pub"],
  "name": "Vector",
  "icon": { "url": "https://blossom.example/…", "key": "<hex>", "nonce": "<hex>", "hash": "<sha256 hex>" },
  "expires_at": 1735689600000,                    // optional, unix ms
  "creator_npub": "<creator pubkey>",             // optional attribution
  "label": "Reddit"                               // optional attribution, at most 64 bytes
}
```

Revoking the link re-posts the same coordinate as a tombstone:

```jsonc
{
  "kind": 33301,
  "pubkey": "<link_signer pubkey>",
  "content": "",
  "tags": [
    ["d", ""],
    ["vsk", "9"]
  ],
  "created_at": 1722400000,
  "sig": "<link_signer signature>"
}
```

### 6.2 Kind 33302 — Community List (CORD-02 §8)

Addressable, one event per fragment, signed by their real key, NIP-44-encrypted to self. A client convenience, never Community state. The `d` tag is the fragment index in decimal; this is fragment `1` of a two-fragment List.

```jsonc
{
  "kind": 33302,
  "pubkey": "<member's real pubkey>",
  "content": "<nip44_encrypt(self, fragment)>",
  "tags": [["d", "1"]],
  "created_at": 1722400000,
  "sig": "<member's real signature>"
}
```

The encrypted fragment's plaintext. Every 32-byte value is unpadded base64url at **any** depth, join material included:

```jsonc
{
  "frags": 2,                                        // how many fragments this List has
  "entries": [
    {
      "community_id": "PxpVK3nQ7sB1yTfWm4dLxZ0aRcE9uHgKjNvOpQrStUv",
      "current": {
        // community_id omitted — inherited from the entry
        "owner":          "nC7hQ2eRtYuIoPaSdFgHjKlZxCvBnM1qW3eR5tY7uI9",
        "owner_salt":     "qhEwR9tYuIoPaSdFgHjKlZxCvBnM1qW3eR5tY7uI0oP",
        "community_root": "d70Xa1QwErTyUiOpAsDfGhJkLzXcVbNm2Qw4Er6Ty8U",
        "root_epoch":     3,
        "control_pk":     "DU8vB4nM6qW1eR3tY5uI7oP9aS0dF2gH4jK6lZ8xC0v",
        "channels": [
          { "id":  "Ch1dQwErTyUiOpAsDfGhJkLzXcVbNm2Qw4Er6Ty8U0i",
            "key": "K3yAsDfGhJkLzXcVbNm1Qw2Er3Ty4Ui5Op6As7Df8Gh",
            "epoch": 2, "name": "staff" }
        ],
        "relays": ["wss://relay.example.com"],
        "name": "Example Community"
      },
      "added_at": 1719800000000                      // ms
      // seed omitted: this membership has never been refounded, so it equals current
    }
  ],
  "tombstones": [
    { "community_id": "u9RfLmWx3PqZtYvBnKjHgFdSaQwErTyUiOp2C4E6G8I", "removed_at": 1722400000000 }
  ]
}
```

Join material is the bundle's membership subset: `owner, owner_salt, community_root, root_epoch, control_pk, channels, relays, name`, plus `control_root` when held (CORD-02 §2) and an optional `rev` (CORD-02 §8) — never the icon, never the link fields. Embedded in an entry it omits `community_id`, inheriting the entry's; standalone (a CORD-06 §1 dissolution payload) it keeps it.

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
      "token": "<hex>",                           // the link's unlock secret AND its merge key
      "signer_sk": "<hex>",                       // the link_signer secret (CORD-05 §2)
      "community_id": "<hex>",
      "url": "https://vectorapp.io/invite/<naddr>#<fragment>",
      "label": "Reddit",                          // optional
      "created_at": 1719800000,
      "expires_at": 1722400000,                   // optional, unix seconds like created_at (the bundle's is ms)
      "epoch": 4                                  // optional, the root epoch it was minted at; a Severing Refounding retires links below its own
    }
  ],
  "tombstones": [
    { "token": "<hex>", "community_id": "<hex>", "expires_at": 1722400000 }   // expires_at optional, the retired link's
  ]
}
```

## 7. Kind 3313 — Direct invite

The one event riding a **standard** NIP-59 giftwrap (CORD-05 §6): ephemeral wrap author, the recipient in the `p` tag, a kind `13` seal — not the reversed stream wrap of §1 — plus the outer `["k", "3313"]` that makes invites indexable. A recipient fetches exactly their invites with `{"kinds":[1059], "#p":["<me>"], "#k":["3313"]}`, no bulk decryption of their giftwrap inbox required. The outer tag is an unsigned hint; the rumor's kind is the authority.

The rumor carries the §6.1 `CommunityInvite` bundle itself as its content — no coordinate, no token, nothing to fetch — validated exactly as a fetched bundle: the self-certifying `community_id`, the CORD-05 §1 bounds, `expires_at`. It is a key handoff, not a standing door: unrevocable once landed, absent from the Registry, and it never flips the Community Public (CORD-05 §6). Nothing happens on receipt — no relay connection, no icon fetch, no Join — until the user accepts.

```jsonc
{
  "id": "<wrap id>",
  "kind": 1059,
  "pubkey": "<ephemeral pubkey, single-use>",
  "content": nip44_encrypt(ephemeral↔recipient, {
    "id": "<seal id>",
    "kind": 13,                                   // standard NIP-59 seal
    "pubkey": "<inviter's real pubkey>",
    "content": nip44_encrypt(inviter↔recipient, {
      "id": "<rumor id>",
      "kind": 3313,
      "pubkey": "<inviter's real pubkey>",
      "content": json_stringify({ /* the CommunityInvite bundle, §6.1 */ }),
      "tags": [],
      "created_at": 1719800000
    }),
    "tags": [],
    "created_at": 1719764213,                     // NIP-59: tweaked into the past
    "sig": "<inviter's real signature>"
  }),
  "tags": [
    ["p", "<recipient pubkey>"],                  // classic NIP-59: fixed recipient, ephemeral author
    ["k", "3313"],                                // the index hint (CORD-05 §6)
    ["expiration", "1735689600"]                  // optional NIP-40, matching the bundle's expires_at
  ],
  "created_at": 1719731502,                       // NIP-59: tweaked into the past
  "sig": "<ephemeral key signature>"
}
```
