/**
 * CORD-03 — Channels: keying, metadata, conversion, message binding.
 */
import { randomBytes } from './bytes.js'
import { channelKey, type GroupKey } from './derive.js'

export interface ChannelMetadata {
  name: string // ≤ 64 bytes, the protocol-wide cap
  private: boolean
  deleted?: boolean // terminal one-way latch
  custom?: Record<string, unknown>
  [k: string]: unknown
}

/** Local keying state for one Channel. */
export interface ChannelKeying {
  channelId: Uint8Array // permanent identity — never changes across conversions
  private: boolean
  channelKey: Uint8Array | null // independent random secret (private only)
  channelEpoch: number // monotonic, never resets; first privatisation is epoch 1
}

export function newPublicChannel(): ChannelKeying {
  return { channelId: randomBytes(32), private: false, channelKey: null, channelEpoch: 0 }
}

/** The one group_key derivation; only the secret and epoch differ by kind. */
export function channelAddress(
  ch: ChannelKeying,
  communityRoot: Uint8Array,
  rootEpoch: number,
): GroupKey {
  return ch.private
    ? channelKey(ch.channelKey!, ch.channelId, ch.channelEpoch)
    : channelKey(communityRoot, ch.channelId, rootEpoch)
}

/**
 * Public → Private: mint an independent key at the NEXT channel_epoch
 * (monotonic, never resetting). The channel_id never changes.
 */
export function privatise(ch: ChannelKeying): ChannelKeying {
  return {
    channelId: ch.channelId,
    private: true,
    channelKey: randomBytes(32),
    channelEpoch: ch.channelEpoch + 1,
  }
}

/** Private → Public: simply derive from the community_root going forward. */
export function publicise(ch: ChannelKeying): ChannelKeying {
  return { channelId: ch.channelId, private: false, channelKey: null, channelEpoch: ch.channelEpoch }
}

/** Deletion is terminal: once deleted, an entity can never be undeleted. */
export function applyMetadataEdit(
  current: ChannelMetadata | null,
  next: ChannelMetadata,
): ChannelMetadata {
  if (current?.deleted) return current // the latch: id never reused, no revival
  return next
}
