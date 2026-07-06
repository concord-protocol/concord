<img width="1280" height="400" alt="Concord-Protocol-Banner" src="https://github.com/user-attachments/assets/5e5faea8-86b6-4af8-82d1-9414fd8855cc"/>

---

> ### concord &nbsp; `/kŏn′kôrd″, kŏng′-/` &nbsp; *noun*
> 1. Harmony or agreement of interests or feelings; accord.
> 2. A treaty establishing peaceful relations.
> 3. *(Grammar)* Agreement between words in person, number, gender, or case.

---
# Concord 

**End-to-end encrypted communities and channels, built on open infrastructure.**

Concord is a protocol for running communities and channels over [Nostr](https://github.com/nostr-protocol/nostr), with no company, no central server, and no intermediary holding your messages or deciding who is in charge. Think of the familiar structure of a platform like Discord, channels, roles, and communities, but where the encryption is real and no single entity controls the room.

## Why Concord?

Every group chat you have ever used has a computer in the middle. It holds every message, knows every member, and is the final authority on who can do what. You trust it to stay online, keep your data private, and never turn on you. It can be subpoenaed, hacked, sold, or switched off. And when it is, your community dies with it.

Concord deletes that computer. The three jobs a central server does get split into pieces that need to trust nobody:

- **Storage & delivery** → dumb, interchangeable **relays** that only ever see encrypted blobs addressed to rotating, meaningless labels. One misbehaves? Use the others.
- **"Who's a member?"** → **key possession.** If you can decrypt the room, you're in it. There is no list to enforce.
- **"Who's in charge?"** → a **signed roster** rooted in the owner's identity. Authority is math every member re-checks for themselves, not a power a server grants.

The result: full Discord-style moderation with owners, admins, roles, kicks, and bans, but authority is a signed list everyone can verify, and messages are sealed so that relays, network observers, and non-members see only noise.

## The Specs

Concord is defined by a series of **CORD** documents. Like Nostr's NIPs, each is a small, self-contained piece that composes into the whole.

| CORD | Title | What it does |
|---|---|---|
| [01](01.md) | Private Streams | The base primitive: a shared-key stream of NIP-59 giftwraps, readable by anyone holding the key, invisible to everyone else. |
| [02](02.md) | Communities | Ties channels into one membership and authority model. Defines the self-certifying `community_id`, the `community_root` access key, epochs, and the Control/Chat/Guestbook planes. |
| [03](03.md) | Channels | Public and Private rooms, each its own sealed plane with its own key derived from the community. |
| [04](04.md) | Roles | Granular, ranked, owner-rooted permissions (Admin, Mod, custom) — validated by every client, enforced by rejection, not by a server. |
| [05](05.md) | Invites | Shareable links whose keys live in an encrypted bundle on relays; the link carries only a locator and an unlock token, so invites revoke without re-keying. |
| [06](06.md) | Rekeys & Refoundings | Post-removal secrecy: rotate a channel's key to cut off a removed member, or re-found the whole community at a new epoch to ban someone for real. |

For a non-normative, at-a-glance reference, [examples.md](examples.md) shows example JSON for every event kind in the registry (CORD-02, Appendix B).

## How it works, at the simplest level

<img width="1920" height="1080" alt="Concord-Protocol-Infographic" src="https://github.com/user-attachments/assets/0482c5c8-973f-4f98-9937-0838e587a7d8" />

A community is just a **shared key** (holding it *is* membership), a **signed roster** anyone can verify, and a handful of **relays** that only ever carry sealed blobs.

Authority is a signature, not a switch. A forged "ban" is simply dropped because it doesn't trace to the owner. And removing someone for real means changing the locks: the community rolls to a new key handed only to who's left.

## Compared to other solutions

Concord isn't the only way to do private messaging on Nostr. It's built for one specific shape, large, Discord-style communities, that the others don't target.

- **[NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) (private DMs).** Can't do communities. Multi-member rooms are an afterthought, and it's vulnerable to DoS issues. Concord is built for communities from the ground up.
- **[NIP-29](https://github.com/nostr-protocol/nips/blob/master/29.md) (relay-based groups).** You have to self-host an entire server just to start a community, and messages are not end-to-end encrypted. Concord needs no server: relays see only noise, and authority is a signed roster every member verifies.
- **[Marmot](https://github.com/marmot-protocol/marmot) (MLS on Nostr).** Uses [MLS](https://www.rfc-editor.org/rfc/rfc9420.html) for forward secrecy and post-compromise security, ideal for small, high-stakes groups. But MLS advances in lockstep (ordered commits, per-device key packages, O(log n) cost per change), which is heavy for large, casual, high-churn rooms. Concord trades those ratcheting guarantees for asynchronous, fold-anytime state that scales to a public community.
- **[Iris Chat](https://irischat.org/) (Double Ratchet chats).** For much the same reasons as Marmot, it aims to replace Signal more than Discord, pairwise ratcheted chats rather than owner-rooted communities.

In short: **NIP-17 is for DMs, NIP-29 trusts the relay, Marmot and Iris Chat secure the small ratcheted group. Concord is built for the scale and shape of a public community.**

## Status

Concord is an evolving specification. The CORD documents above are the source of truth. Contributions, questions, and review are welcome.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

You are free to use, copy, modify, merge, publish, distribute, sublicense, and build upon this project for any purpose, commercial or personal, as long as the original license notice is included in all copies or substantial portions of the software. This project is provided as-is, without warranty of any kind. Contributions are welcome and will be released under the same license.
