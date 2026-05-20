/**
 * Per-user block list per DELIVERY.md §4.
 *
 * The list is server-readable only when explicitly decrypted by
 * the owning user's authenticated client device. Production
 * deployments store entries encrypted at rest per §6.3 and unwrap
 * on demand.
 *
 * @module
 */

import type { Acknowledgment } from "./ack.js";

/** Entity kinds per §4.3. */
export type BlocklistEntityType = "user" | "domain" | "server";

/** Delivery-time applicability per §4.4. */
export type BlocklistScope = "all" | "direct" | "group";

/** One entry in a {@link BlockList}. */
export interface BlockEntry {
  id: string;
  entity: BlocklistEntity;
  acknowledgment: Acknowledgment;
  reason?: string;
  scope: BlocklistScope;
  /** ISO 8601 UTC. */
  created_at: string;
  /** ISO 8601 UTC; absent for permanent blocks. */
  expires_at?: string;
  created_by_device_id: string;
  extensions?: Record<string, unknown>;
}

/**
 * Block-list entity. Only the field appropriate for `type` is
 * populated.
 */
export interface BlocklistEntity {
  type: BlocklistEntityType;
  /** Required when `type === "user"`. */
  address?: string;
  /** Required when `type === "domain"`. */
  domain?: string;
  /** Required when `type === "server"`. */
  hostname?: string;
}

/** A user's full block list per §4.1. */
export interface BlockList {
  user_id: string;
  list_version: number;
  entries: BlockEntry[];
}

/** Sender-side identifiers used by {@link matchBlockList}. */
export interface BlockListSender {
  /** Full sender address from `brief.from`. */
  address?: string;
  /** Verified sender domain from `postmark.from_domain`. */
  domain?: string;
  /** SEMP server hostname through which the envelope was routed. */
  server?: string;
  /** True when the envelope is part of a group / mailing-list thread. */
  isGroup?: boolean;
}

/**
 * Return the most-specific entry that matches `sender`, or null
 * when no entry applies. Entity-type precedence per §4.4:
 * `user > server > domain`.
 *
 * Entries past `expires_at` are skipped (no clock-skew tolerance
 * applied here - callers that want the §4.4 grace window evaluate
 * expiry themselves).
 *
 * All comparisons are case-insensitive.
 */
export function matchBlockList(
  list: BlockList | null,
  sender: BlockListSender,
  now: Date = new Date(),
): BlockEntry | null {
  if (list === null || list.entries.length === 0) {
    return null;
  }
  const address = (sender.address ?? "").toLowerCase();
  const domain = (sender.domain ?? "").toLowerCase();
  const server = (sender.server ?? "").toLowerCase();
  const isGroup = sender.isGroup ?? false;

  const RANK_DOMAIN = 1;
  const RANK_SERVER = 2;
  const RANK_USER = 3;
  let bestRank = 0;
  let bestEntry: BlockEntry | null = null;

  for (const entry of list.entries) {
    if (entry.expires_at !== undefined && entry.expires_at !== "") {
      const exp = Date.parse(entry.expires_at);
      if (!Number.isNaN(exp) && exp <= now.getTime()) {
        continue;
      }
    }
    if (!scopeApplies(entry.scope, isGroup)) {
      continue;
    }
    let rank = 0;
    switch (entry.entity.type) {
      case "user":
        if (
          address === "" ||
          (entry.entity.address ?? "").toLowerCase() !== address
        ) {
          continue;
        }
        rank = RANK_USER;
        break;
      case "server":
        if (
          server === "" ||
          (entry.entity.hostname ?? "").toLowerCase() !== server
        ) {
          continue;
        }
        rank = RANK_SERVER;
        break;
      case "domain":
        if (
          domain === "" ||
          (entry.entity.domain ?? "").toLowerCase() !== domain
        ) {
          continue;
        }
        rank = RANK_DOMAIN;
        break;
      default:
        continue; // unknown entity type - forward-compat ignore
    }
    if (rank > bestRank) {
      bestRank = rank;
      bestEntry = entry;
      if (bestRank === RANK_USER) {
        return bestEntry;
      }
    }
  }
  return bestEntry;
}

function scopeApplies(scope: BlocklistScope, isGroup: boolean): boolean {
  switch (scope) {
    case "all":
      return true;
    case "direct":
      return !isGroup;
    case "group":
      return isGroup;
    default:
      // Empty/unknown scope: forward-compat treats as "all".
      return scope === undefined || scope === ("" as never);
  }
}

/**
 * Minimal lookup interface the delivery pipeline consumes at step
 * 8 of DELIVERY.md §2. Implementations return the recipient's full
 * block list. Returning null is the canonical "no list configured"
 * answer and is treated as "no entries match".
 */
export interface BlockListLookup {
  lookup(recipient: string): Promise<BlockList | null>;
}

/** Trivial in-memory {@link BlockListLookup} keyed by recipient address. */
export class StaticBlockListLookup implements BlockListLookup {
  private readonly lists: Map<string, BlockList>;

  constructor(lists: Record<string, BlockList> = {}) {
    this.lists = new Map();
    for (const [k, v] of Object.entries(lists)) {
      this.lists.set(k.toLowerCase(), v);
    }
  }

  async lookup(recipient: string): Promise<BlockList | null> {
    return this.lists.get(recipient.toLowerCase()) ?? null;
  }
}
