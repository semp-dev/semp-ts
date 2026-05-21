/**
 * Envelope size-bucket padding per ENVELOPE.md §2.4.
 *
 * `fillPadding` populates `env.padding` with a base64-alphabet filler
 * string whose length brings the serialized envelope's wire size
 * exactly onto the bucket chosen from the configured size sequence.
 * This is the privacy-critical primitive that prevents an on-path
 * observer from learning the underlying envelope size.
 *
 * The size sequence is the default power-of-two curve starting at
 * 4 KB by default; operators tune this via `bucketSequence` per the
 * spec's "Operator tuning" allowance.
 *
 * @module
 */

import {
  type Envelope,
} from "./compose.js";
import {
  DefaultMaxEnvelopeSize,
  MinEnvelopeSizeBucket,
  selectSizeBucket,
} from "./buckets.js";

/** Exact base64 length of an Ed25519 signature (64 raw bytes -> 88 chars). */
export const Ed25519SignatureB64Len = 88;

/** Exact base64 length of an HMAC-SHA-256 output (32 raw bytes -> 44 chars). */
export const HMACSHA256B64Len = 44;

/**
 * Pool of single base64-alphabet characters used to extend a base64
 * filler by 1, 2, or 3 bytes when the bucket target requires
 * non-multiple-of-4 padding length.
 */
const Base64AlphabetFillers =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Inputs to {@link fillPadding}. */
export interface PadConfig {
  /** Negotiated session ceiling. Zero means {@link DefaultMaxEnvelopeSize}. */
  maxEnvelopeSize?: number;
  /**
   * Custom bucket sequence overriding the default power-of-two
   * curve. Must be strictly increasing, with the first element
   * at or above {@link MinEnvelopeSizeBucket} and the last at or
   * below the effective ceiling. Operator tuning per §2.4.1.
   */
  bucketSequence?: number[];
  /** Random source for filler bytes. Defaults to `globalThis.crypto.getRandomValues`. */
  rand?: (n: number) => Uint8Array;
}

/**
 * Populate `env.padding` so that `JSON.stringify(env)` lands on
 * exactly the size of the chosen bucket. Safe to call before OR
 * after `compose` populates `seal.signature` / `seal.session_mac` -
 * if either is empty, fillPadding temporarily substitutes a
 * fixed-length placeholder for measurement so the post-sign size
 * is correct either way.
 *
 * Mutates `env` in place. Returns the chosen bucket size for
 * caller-side assertions.
 */
export function fillPadding(env: Envelope, cfg: PadConfig = {}): number {
  const ceiling = cfg.maxEnvelopeSize ?? DefaultMaxEnvelopeSize;
  if (cfg.bucketSequence !== undefined && cfg.bucketSequence.length > 0) {
    validateBucketSequence(cfg.bucketSequence, ceiling);
  }
  const rand = cfg.rand ?? defaultRand;

  // Substitute placeholders for empty signature / MAC so the
  // measurement reflects the final post-sign wire size.
  const origSig = env.seal.signature;
  const origMac = env.seal.session_mac;
  if (origSig === "") {
    env.seal.signature = "A".repeat(Ed25519SignatureB64Len);
  }
  if (origMac === "") {
    env.seal.session_mac = "A".repeat(HMACSHA256B64Len);
  }
  try {
    env.padding = "";
    const baselineBytes = utf8ByteLength(JSON.stringify(env));
    const bucket = pickBucket(baselineBytes, ceiling, cfg.bucketSequence);
    if (baselineBytes === bucket) {
      return bucket;
    }
    const targetPadLen = bucket - baselineBytes;
    if (targetPadLen < 0) {
      throw new Error(
        `envelope: baseline ${baselineBytes} exceeds bucket ${bucket}`,
      );
    }
    env.padding = buildPaddingValue(targetPadLen, rand);

    // Final assertion: the envelope now serializes to exactly bucket.
    const finalBytes = utf8ByteLength(JSON.stringify(env));
    if (finalBytes !== bucket) {
      throw new Error(
        `envelope: padding did not land on bucket ${bucket} (got ${finalBytes})`,
      );
    }
    return bucket;
  } finally {
    if (origSig === "") {
      env.seal.signature = "";
    }
    if (origMac === "") {
      env.seal.session_mac = "";
    }
  }
}

/**
 * Build a string of exactly `targetLen` base64-alphabet characters,
 * drawn from a CSPRNG. The bulk is a base64 encoding of CSPRNG
 * bytes; the final 1-3 characters (when targetLen is not reachable
 * by `btoa` 4-character chunks) are CSPRNG-seeded alphabet
 * characters appended for length alignment per §2.4.2.
 */
export function buildPaddingValue(
  targetLen: number,
  rand: (n: number) => Uint8Array = defaultRand,
): string {
  if (!Number.isInteger(targetLen) || targetLen < 0) {
    throw new Error(`envelope: negative padding length ${targetLen}`);
  }
  if (targetLen === 0) {
    return "";
  }
  // base64 emits 4 chars per 3 input bytes. Pick the largest
  // multiple of 4 ≤ targetLen as the base64-encoded portion; the
  // remainder (0-3 chars) is filled from the alphabet pool.
  const baseChars = targetLen - (targetLen % 4);
  const inputBytes = (baseChars / 4) * 3;
  const out: string[] = [];
  if (inputBytes > 0) {
    const buf = rand(inputBytes);
    out.push(base64Encode(buf));
  }
  const fillerCount = targetLen - baseChars;
  if (fillerCount > 0) {
    const seed = rand(fillerCount);
    for (let i = 0; i < fillerCount; i++) {
      const idx = (seed[i] ?? 0) % Base64AlphabetFillers.length;
      out.push(Base64AlphabetFillers[idx] ?? "A");
    }
  }
  return out.join("");
}

function pickBucket(
  unpaddedSize: number,
  ceiling: number,
  sequence: number[] | undefined,
): number {
  if (sequence === undefined || sequence.length === 0) {
    return selectSizeBucket(unpaddedSize, ceiling);
  }
  for (const b of sequence) {
    if (b >= unpaddedSize) {
      return b;
    }
  }
  return ceiling;
}

function validateBucketSequence(seq: number[], ceiling: number): void {
  if ((seq[0] ?? 0) < MinEnvelopeSizeBucket) {
    throw new Error(
      `envelope: bucket sequence first element ${seq[0]} is below protocol floor ${MinEnvelopeSizeBucket}`,
    );
  }
  for (let i = 1; i < seq.length; i++) {
    if ((seq[i] ?? 0) <= (seq[i - 1] ?? 0)) {
      throw new Error(
        `envelope: bucket sequence is not strictly increasing at index ${i}`,
      );
    }
  }
  if ((seq[seq.length - 1] ?? 0) > ceiling) {
    throw new Error(
      `envelope: bucket sequence last element ${seq[seq.length - 1]} exceeds max_envelope_size ${ceiling}`,
    );
  }
}

function utf8ByteLength(s: string): number {
  if (typeof Buffer !== "undefined") {
    return Buffer.byteLength(s, "utf8");
  }
  return new TextEncoder().encode(s).length;
}

function defaultRand(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
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
