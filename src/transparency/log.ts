/**
 * Operator-runnable transparency log per TRANSPARENCY.md §2.2.
 *
 * Maintains an append-only sequence of leaf hashes; issues
 * SignedTreeHeads; computes RFC 6962 inclusion + consistency
 * proofs against the current state.
 *
 * The reference implementation holds entries and leaf hashes in
 * memory. Production deployments wrap a durable backend; the
 * operations factor cleanly into a Store interface when needed.
 *
 * @module
 */

import {
  type ConsistencyProof,
  type InclusionProof,
  type LogEntry,
  type SignedTreeHead,
} from "./types.js";
import {
  auditPath,
  encodeHash,
  hashLeafFromEntry,
  subproof,
  subtreeRoot,
} from "./merkle.js";
import { signSTH, validateLogEntry } from "./sign.js";

/** Inputs to the {@link Log} constructor. */
export interface LogConfig {
  /** 32-byte Ed25519 secret seed used to sign every issued STH. */
  domainSigningSeed: Uint8Array;
  /** Lowercase-hex SHA-256 fingerprint of the domain signing pub. */
  domainKeyId: string;
  /** Wall-clock for STH timestamps. Defaults to `() => new Date()`. */
  nowFn?: () => Date;
}

/**
 * Append-only transparency log. Concurrency-safe under the JS
 * single-threaded model: every method runs to completion before
 * the next; no internal mutex needed.
 */
export class Log {
  private readonly entries: LogEntry[] = [];
  private readonly leaves: Uint8Array[] = [];
  private readonly cfg: LogConfig;

  constructor(cfg: LogConfig) {
    if (cfg.domainKeyId === "") {
      throw new Error("transparency: log requires domainKeyId");
    }
    if (cfg.domainSigningSeed.length !== 32) {
      throw new Error("transparency: log requires 32-byte domainSigningSeed");
    }
    this.cfg = cfg;
  }

  /**
   * Validate `entry`, hash its leaf, and append. Returns the
   * assigned 0-based leaf index. Does NOT verify any signature on
   * the entry — admission policy is the caller's concern.
   */
  append(entry: LogEntry): number {
    validateLogEntry(entry);
    const leaf = hashLeafFromEntry(entry);
    this.entries.push(entry);
    this.leaves.push(leaf);
    return this.leaves.length - 1;
  }

  /** Current tree size. */
  size(): number {
    return this.leaves.length;
  }

  /**
   * Return the entry at `index`, or `null` when out of range.
   * The returned object is a reference; callers that mutate must
   * clone first.
   */
  entry(index: number): LogEntry | null {
    if (!Number.isInteger(index) || index < 0 || index >= this.entries.length) {
      return null;
    }
    return this.entries[index] ?? null;
  }

  /** Compute the current root hash and return a signed tree head. */
  issueSTH(): SignedTreeHead {
    const root = subtreeRoot(this.leaves.slice());
    const now = (this.cfg.nowFn ?? (() => new Date()))();
    const preSign: SignedTreeHead = {
      log_size: this.leaves.length,
      root_hash: encodeHash(root),
      timestamp: isoSecond(now),
      signature: { algorithm: "", key_id: "", value: "" },
    };
    return signSTH({
      sth: preSign,
      domainSigningSeed: this.cfg.domainSigningSeed,
      domainKeyId: this.cfg.domainKeyId,
    }).sth;
  }

  /**
   * RFC 6962 audit path for `leafIndex` against `treeSize`. Throws
   * when `leafIndex >= treeSize` or `treeSize > size()`.
   */
  inclusionProof(leafIndex: number, treeSize: number): InclusionProof {
    if (!Number.isInteger(treeSize) || treeSize <= 0) {
      throw new Error(`transparency: invalid treeSize ${treeSize}`);
    }
    if (treeSize > this.leaves.length) {
      throw new Error(
        `transparency: treeSize ${treeSize} exceeds current size ${this.leaves.length}`,
      );
    }
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
      throw new Error(
        `transparency: leafIndex ${leafIndex} out of [0, ${treeSize})`,
      );
    }
    const leaves = this.leaves.slice(0, treeSize);
    const siblings = auditPath(leafIndex, leaves);
    return {
      log_size: treeSize,
      leaf_hash: encodeHash(leaves[leafIndex]!),
      leaf_index: leafIndex,
      path: siblings.map(encodeHash),
    };
  }

  /**
   * RFC 6962 consistency proof from `firstSize` to `secondSize`.
   * Both MUST be in `(0, size()]`; `firstSize` MUST be `<= secondSize`.
   */
  consistencyProof(firstSize: number, secondSize: number): ConsistencyProof {
    if (
      !Number.isInteger(firstSize) ||
      !Number.isInteger(secondSize) ||
      firstSize <= 0 ||
      secondSize <= 0
    ) {
      throw new Error(
        `transparency: invalid sizes (${firstSize}, ${secondSize})`,
      );
    }
    if (firstSize > secondSize) {
      throw new Error(
        `transparency: firstSize ${firstSize} > secondSize ${secondSize}`,
      );
    }
    if (secondSize > this.leaves.length) {
      throw new Error(
        `transparency: secondSize ${secondSize} exceeds current size ${this.leaves.length}`,
      );
    }
    const second = this.leaves.slice(0, secondSize);
    const path = subproof(firstSize, second, true);
    return {
      from_size: firstSize,
      to_size: secondSize,
      path: path.map(encodeHash),
    };
  }
}

function isoSecond(d: Date): string {
  // Strip milliseconds — STH timestamps are second-precision per
  // CONFORMANCE.md §9.3.
  const iso = d.toISOString();
  return iso.replace(/\.\d{3}Z$/, "Z");
}
