/**
 * RFC 6962 Merkle tree math for SEMP key transparency.
 *
 * The leaf hash is `SHA-256(0x00 || canonical_json_bytes)`; an
 * interior node is `SHA-256(0x01 || left || right)`.
 *
 * This module covers:
 *  - {@link hashLeaf} / {@link hashInterior}: the per-node hash
 *    primitives
 *  - {@link verifyInclusionProof}: §3.1 audit-path verification
 *  - {@link verifyConsistencyProof}: §3.2 prefix verification
 *  - {@link subtreeRoot}, {@link auditPath}, {@link subproof}: the
 *    PROOF/PATH/SUBPROOF subroutines from RFC 6962 §2.1
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { marshal as canonicalMarshal } from "../canonical/index.js";

import {
  type ConsistencyProof,
  type InclusionProof,
  type LogEntry,
  InteriorPrefix,
  LeafPrefix,
} from "./types.js";

/**
 * `SHA-256(0x00 || entryBytes)` per §2.2 / RFC 6962 §2.1. The
 * caller MUST use the same canonical bytes the log producer used.
 */
export function hashLeaf(entryBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + entryBytes.length);
  buf[0] = LeafPrefix;
  buf.set(entryBytes, 1);
  return sha256(buf);
}

/**
 * Marshal `entry` to canonical JSON and return {@link hashLeaf} of
 * the result.
 */
export function hashLeafFromEntry(entry: LogEntry): Uint8Array {
  return hashLeaf(canonicalMarshal(entry as unknown as Record<string, unknown>));
}

/** `SHA-256(0x01 || left || right)` per RFC 6962 §2.1. */
export function hashInterior(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + 32 + 32);
  buf[0] = InteriorPrefix;
  buf.set(left, 1);
  buf.set(right, 33);
  return sha256(buf);
}

/**
 * Verify `proof` against `rootHash` per RFC 6962 §2.1.1. Returns
 * true on success.
 */
export function verifyInclusionProof(
  proof: InclusionProof,
  rootHash: Uint8Array,
): boolean {
  if (proof.log_size <= 0) {
    return false;
  }
  if (proof.leaf_index < 0 || proof.leaf_index >= proof.log_size) {
    return false;
  }
  let leaf: Uint8Array;
  let siblings: Uint8Array[];
  try {
    leaf = decodeHash(proof.leaf_hash);
    siblings = decodeHashes(proof.path);
  } catch {
    return false;
  }
  let computed: Uint8Array;
  try {
    computed = computeRootFromInclusion(
      proof.leaf_index,
      proof.log_size,
      leaf,
      siblings,
    );
  } catch {
    return false;
  }
  return bytesEqual(computed, rootHash);
}

function computeRootFromInclusion(
  leafIndex: number,
  treeSize: number,
  leaf: Uint8Array,
  siblings: Uint8Array[],
): Uint8Array {
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leaf;
  let pathIdx = 0;
  while (sn > 0) {
    if (pathIdx >= siblings.length) {
      throw new Error("transparency: inclusion proof too short");
    }
    const s = siblings[pathIdx]!;
    pathIdx++;
    if ((fn & 1) === 1 || fn === sn) {
      r = hashInterior(s, r);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      r = hashInterior(r, s);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  if (pathIdx !== siblings.length) {
    throw new Error(
      `transparency: inclusion proof has ${siblings.length - pathIdx} unused siblings`,
    );
  }
  return r;
}

/**
 * Verify `proof` per RFC 6962 §2.1.2. Returns true when the proof
 * attests that the tree of size `from_size` (with `firstRoot`) is a
 * prefix of the tree of size `to_size` (with `secondRoot`).
 */
export function verifyConsistencyProof(
  proof: ConsistencyProof,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
): boolean {
  if (proof.from_size < 0 || proof.to_size < 0) {
    return false;
  }
  if (proof.from_size > proof.to_size) {
    return false;
  }
  if (proof.from_size === proof.to_size) {
    if (proof.path.length !== 0) {
      return false;
    }
    return bytesEqual(firstRoot, secondRoot);
  }
  if (proof.from_size === 0) {
    // Trivially consistent; path expected empty per RFC 6962.
    return proof.path.length === 0;
  }
  let siblings: Uint8Array[];
  try {
    siblings = decodeHashes(proof.path);
  } catch {
    return false;
  }
  let recomputed: { first: Uint8Array; second: Uint8Array };
  try {
    recomputed = computeRootsFromConsistency(
      proof.from_size,
      proof.to_size,
      firstRoot,
      siblings,
    );
  } catch {
    return false;
  }
  return (
    bytesEqual(recomputed.first, firstRoot) &&
    bytesEqual(recomputed.second, secondRoot)
  );
}

function computeRootsFromConsistency(
  firstSize: number,
  secondSize: number,
  firstRoot: Uint8Array,
  path: Uint8Array[],
): { first: Uint8Array; second: Uint8Array } {
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while ((fn & 1) === 1) {
    fn >>>= 1;
    sn >>>= 1;
  }

  let fr: Uint8Array;
  let sr: Uint8Array;
  let pathIdx = 0;
  if (fn !== 0) {
    if (pathIdx >= path.length) {
      throw new Error("transparency: consistency proof too short");
    }
    fr = path[pathIdx]!;
    sr = path[pathIdx]!;
    pathIdx++;
  } else {
    fr = firstRoot;
    sr = firstRoot;
  }
  while (sn > 0) {
    if (pathIdx >= path.length) {
      throw new Error("transparency: consistency proof too short");
    }
    const c = path[pathIdx]!;
    pathIdx++;
    if ((fn & 1) === 1 || fn === sn) {
      fr = hashInterior(c, fr);
      sr = hashInterior(c, sr);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      sr = hashInterior(sr, c);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  if (pathIdx !== path.length) {
    throw new Error(
      `transparency: consistency proof has ${path.length - pathIdx} unused hashes`,
    );
  }
  return { first: fr, second: sr };
}

/**
 * Largest power of 2 strictly less than `n`. Used by RFC 6962
 * PATH and SUBPROOF construction.
 */
export function largestPowerOfTwoLessThan(n: number): number {
  if (n <= 1) {
    return 0;
  }
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/**
 * MTH(D[0:n]) per RFC 6962 §2.1. An empty input returns the all-zeros
 * 32-byte hash; the spec actually defines MTH(empty) = SHA-256("")
 * but inclusion / consistency proofs never operate on an empty
 * subtree directly.
 */
export function subtreeRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    return new Uint8Array(32);
  }
  if (leaves.length === 1) {
    return leaves[0]!;
  }
  const k = largestPowerOfTwoLessThan(leaves.length);
  const left = subtreeRoot(leaves.slice(0, k));
  const right = subtreeRoot(leaves.slice(k));
  return hashInterior(left, right);
}

/** PATH(m, D[0:n]) per RFC 6962 §2.1.1. */
export function auditPath(m: number, leaves: Uint8Array[]): Uint8Array[] {
  const n = leaves.length;
  if (n <= 1) {
    return [];
  }
  const k = largestPowerOfTwoLessThan(n);
  if (m < k) {
    return [...auditPath(m, leaves.slice(0, k)), subtreeRoot(leaves.slice(k))];
  }
  return [
    ...auditPath(m - k, leaves.slice(k)),
    subtreeRoot(leaves.slice(0, k)),
  ];
}

/** SUBPROOF(m, D[0:n], b) per RFC 6962 §2.1.2. */
export function subproof(
  m: number,
  leaves: Uint8Array[],
  b: boolean,
): Uint8Array[] {
  const n = leaves.length;
  if (m === n) {
    if (b) {
      return [];
    }
    return [subtreeRoot(leaves)];
  }
  const k = largestPowerOfTwoLessThan(n);
  if (m <= k) {
    return [...subproof(m, leaves.slice(0, k), b), subtreeRoot(leaves.slice(k))];
  }
  return [
    ...subproof(m - k, leaves.slice(k), false),
    subtreeRoot(leaves.slice(0, k)),
  ];
}

// ---------------------------------------------------------------------------
// Helpers

/** Base64-encode a 32-byte hash for the wire form. */
export function encodeHash(h: Uint8Array): string {
  if (h.length !== 32) {
    throw new Error(`transparency: hash length ${h.length}, want 32`);
  }
  return base64Encode(h);
}

function decodeHash(s: string): Uint8Array {
  const out = base64Decode(s);
  if (out.length !== 32) {
    throw new Error(`transparency: hash length ${out.length}, want 32`);
  }
  return out;
}

function decodeHashes(items: string[]): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < items.length; i++) {
    try {
      out.push(decodeHash(items[i] ?? ""));
    } catch (err) {
      throw new Error(
        `transparency: path[${i}]: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function base64Encode(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
}

function base64Decode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}
