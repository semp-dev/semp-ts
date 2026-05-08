/**
 * Helpers for the JSON-driven vectors runner. Path resolution,
 * file loading, decoders, and the typed shape of a vector entry.
 *
 * The runner is the gating criterion for cross-implementation
 * interop: a semp-ts change that breaks a vector breaks
 * compatibility with every other SEMP implementation that passes
 * the same vectors.
 *
 * @module
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Top-level shape of a vectors `*.json` file. */
export interface VectorFile {
  version: string;
  category: string;
  description: string;
  spec_reference: string;
  vectors: VectorEntry[];
}

/**
 * Per-test-case shape. A vector is either single-case (carries
 * `inputs`/`expected`) or table-shape (carries `samples`); the
 * runner detects which by checking for `samples` first.
 */
export interface VectorEntry {
  id: string;
  must_reject?: boolean;
  rejection_class?: string;
  description: string;
  spec_reference: string;
  rule?: string;
  inputs?: unknown;
  expected?: unknown;
  intermediates?: unknown;
  samples?: unknown[];
}

/**
 * Resolve the vectors directory. `SEMP_VECTORS_DIR` overrides;
 * default is `../semp-spec/vectors/v1.0.0/` relative to the
 * package root (the canonical sibling-checkout layout). Returns
 * null if neither resolves so the caller can `test.skip` cleanly.
 */
export function findVectorsDir(): string | null {
  const env = process.env.SEMP_VECTORS_DIR;
  if (env && isDir(env)) {
    return resolve(env);
  }
  // The test file lives under semp-ts/test/vectors/. Walk up two
  // levels to reach the package root, then over to semp-spec.
  const here = fileURLToPath(import.meta.url);
  const candidates = [
    join(dirname(here), "..", "..", "..", "semp-spec", "vectors", "v1.0.0"),
    join(dirname(here), "..", "..", "..", "..", "semp-spec", "vectors", "v1.0.0"),
  ];
  for (const c of candidates) {
    const abs = resolve(c);
    if (isDir(abs)) {
      return abs;
    }
  }
  return null;
}

function isDir(p: string): boolean {
  try {
    return existsSync(p) && statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Load and parse a single vectors `.json` file. */
export function loadVectorFile(path: string): VectorFile {
  const raw = readFileSync(path, "utf-8");
  return JSON.parse(raw) as VectorFile;
}

// ---------------------------------------------------------------------------
// Field accessors
//
// The vectors encode bytes as hex/b64-suffixed strings so the file
// is human-readable. These helpers decode by suffix and provide
// typed access to nested fields.

/** Decode a hex string to bytes. */
export function decodeHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) {
    throw new Error(`hex length ${s.length} is odd`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`bad hex at offset ${i * 2}: ${s.slice(i * 2, i * 2 + 2)}`);
    }
    out[i] = byte;
  }
  return out;
}

/** Decode a base64 string (RFC 4648 §4, padded) to bytes. */
export function decodeBase64(s: string): Uint8Array {
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

/** Encode bytes to hex (lowercase, no separators). */
export function encodeHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += (b[i] ?? 0).toString(16).padStart(2, "0");
  }
  return s;
}

/** Encode bytes to base64 (RFC 4648 §4, padded). */
export function encodeBase64(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
}

/** Constant-time equality check on two byte slices. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Type guard + accessor: pull a string field from a generic JSON
 * object. Throws if the field is missing or not a string. Use the
 * `optional` form when the field may legitimately be absent.
 */
export function getString(obj: unknown, field: string): string {
  const v = getOptionalString(obj, field);
  if (v === undefined) {
    throw new Error(`expected field ${field}: missing`);
  }
  return v;
}

export function getOptionalString(obj: unknown, field: string): string | undefined {
  if (!isRecord(obj)) {
    return undefined;
  }
  const v = obj[field];
  if (typeof v !== "string") {
    return undefined;
  }
  return v;
}

export function getInt(obj: unknown, field: string): number {
  if (!isRecord(obj)) {
    throw new Error(`expected object, got ${typeof obj}`);
  }
  const v = obj[field];
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error(`expected integer field ${field}`);
  }
  return v;
}

export function getBool(obj: unknown, field: string): boolean {
  if (!isRecord(obj)) {
    return false;
  }
  const v = obj[field];
  return typeof v === "boolean" && v;
}

/** Pull a nested field of any type. Returns undefined if missing. */
export function getField(obj: unknown, field: string): unknown {
  if (!isRecord(obj)) {
    return undefined;
  }
  return obj[field];
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
