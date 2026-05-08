/**
 * Signed-document compose helpers.
 *
 * Every Ed25519-signed SEMP document — closure request, configuration
 * update, user policy, migration record, sender-signature enclosure,
 * delivery receipt, transparency STH, recovery manifest, recovery
 * share, handshake response/accepted/rejected — follows the same
 * shape: build the document with the signature value blanked,
 * canonicalize per ENVELOPE.md §4.3, prepend a domain-separation
 * prefix, sign with Ed25519, write the signature back into the
 * document.
 *
 * `signSignedDoc` runs that flow on a deep copy of the input and
 * returns both the populated document AND the bare base64 signature.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import { sign } from "./sign.js";

/** Inputs to a signed-document compose. */
export interface SignSignedDocSpec {
  /**
   * The pre-sign document. Must contain the signature path with the
   * value field present (any string content; will be blanked before
   * canonicalization).
   */
  preSignJSON: Record<string, unknown>;
  /** 32-byte Ed25519 secret seed. */
  seed: Uint8Array;
  /** Dotted path to the signature value (e.g. "signature.value"). */
  signaturePath: string;
  /** Domain-separation prefix from ENVELOPE.md §4.3. */
  prefix: string;
}

/** Result of a signed-document compose. */
export interface SignSignedDocResult {
  /** Deep copy of preSignJSON with the signature value populated. */
  signedJSON: Record<string, unknown>;
  /** Canonical bytes that were signed (with the value blanked). */
  canonicalBlanked: Uint8Array;
  /** Base64-encoded Ed25519 signature. */
  signatureB64: string;
}

/**
 * Compose a signed document. Deep-clones the input, blanks the
 * signature value field, canonicalizes, prepends the prefix,
 * Ed25519-signs the result with `seed`, and writes the signature
 * back into the cloned document at the same path.
 */
export function signSignedDoc(spec: SignSignedDocSpec): SignSignedDocResult {
  const clone = deepCloneJSON(spec.preSignJSON);
  setPath(clone, spec.signaturePath, "");
  const blanked = canonicalMarshal(clone);
  const signingInput = concat(new TextEncoder().encode(spec.prefix), blanked);
  const sig = sign(spec.seed, signingInput);
  const sigB64 = base64Encode(sig);
  setPath(clone, spec.signaturePath, sigB64);
  return { signedJSON: clone, canonicalBlanked: blanked, signatureB64: sigB64 };
}

function setPath(m: Record<string, unknown>, path: string, value: string): void {
  const parts = path.split(".");
  let cur: Record<string, unknown> = m;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (key === undefined) {
      throw new Error(`signSignedDoc: empty path segment in ${path}`);
    }
    const next = cur[key];
    if (typeof next !== "object" || next === null || Array.isArray(next)) {
      throw new Error(`signSignedDoc: path ${path}: segment ${key} is not an object`);
    }
    cur = next as Record<string, unknown>;
  }
  const leaf = parts[parts.length - 1];
  if (leaf === undefined) {
    throw new Error(`signSignedDoc: path ${path} is empty`);
  }
  cur[leaf] = value;
}

function deepCloneJSON(v: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(v)) as Record<string, unknown>;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
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
