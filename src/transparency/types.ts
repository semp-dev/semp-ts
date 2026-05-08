/**
 * Wire-record types for SEMP key transparency per TRANSPARENCY.md.
 *
 * A domain supporting key transparency maintains a single
 * append-only RFC 6962 Merkle tree of key events. Clients fetching
 * keys augment the response with a Signed Tree Head (STH) and an
 * inclusion proof so a third party can verify the published key
 * matches the same key the domain has shown to every other client.
 *
 * @module
 */

/** Wire format version for log entries. */
export const LogEntryVersion = "1.0.0";

/** Wire format version for signed tree heads. */
export const SignedTreeHeadVersion = "1.0.0";

/** RFC 6962 leaf domain-separation byte. */
export const LeafPrefix = 0x00;

/** RFC 6962 interior-node domain-separation byte. */
export const InteriorPrefix = 0x01;

/**
 * STH staleness ceiling per §2.3 — verifiers reject STHs whose
 * timestamp is more than this old.
 */
export const MaxSTHFreshnessMs = 60 * 60 * 1000;

/** Kind of key event recorded as a leaf, per §2.2. */
export type LogEntryEvent = "publish" | "rotate" | "revoke";

/** SEMP key kind being recorded, per §2.2 + KEY.md §1. */
export type LogKeyType = "identity" | "encryption";

/**
 * One leaf of the transparency Merkle tree per §2.2. Insertion
 * order is the leaf's position; the log MUST NOT remove or
 * reorder leaves.
 */
export interface LogEntry {
  event: LogEntryEvent;
  user_id: string;
  key_id: string;
  key_type: LogKeyType;
  algorithm: string;
  /** Base64-encoded public key. */
  public_key: string;
  /** ISO 8601 UTC timestamp. */
  created: string;
  /** ISO 8601 UTC; nullable. */
  expires?: string | null;
  /** Populated only on `revoke`. */
  revoked_at?: string | null;
  /** Populated only on `revoke`. */
  revoked_reason?: string | null;
  /** Populated only on `rotate` — names the key being rotated out. */
  supersedes?: string | null;
  /** ISO 8601 UTC; the log's timestamp for this insertion. */
  log_timestamp: string;
}

/** Reusable signature block per §2.3. */
export interface TransparencySignature {
  algorithm: string;
  key_id: string;
  /** Base64 signature. */
  value: string;
}

/**
 * Periodic published commitment per §2.3. Domains MUST publish a
 * fresh STH at least every hour; verifiers reject STHs older than
 * {@link MaxSTHFreshnessMs}.
 */
export interface SignedTreeHead {
  log_size: number;
  /** Base64 of the 32-byte SHA-256 root. */
  root_hash: string;
  /** ISO 8601 UTC timestamp. */
  timestamp: string;
  signature: TransparencySignature;
}

/**
 * §3.1 proof that `leaf_hash` sits at `leaf_index` in a tree of
 * size `log_size` whose root is published by an STH.
 */
export interface InclusionProof {
  log_size: number;
  /** Base64 of 32-byte SHA-256 leaf hash. */
  leaf_hash: string;
  leaf_index: number;
  /** Base64 sibling hashes, root-ward order. */
  path: string[];
}

/**
 * §3.2 proof that the tree of size `from_size` is a prefix of the
 * tree of size `to_size`.
 */
export interface ConsistencyProof {
  from_size: number;
  to_size: number;
  /** Base64 hashes per RFC 6962 §2.1.2. */
  path: string[];
}
