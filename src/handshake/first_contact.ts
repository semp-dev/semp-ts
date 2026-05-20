/**
 * First-contact PoW prefix binding per HANDSHAKE.md §2.2a.3.
 *
 * When a recipient server demands proof-of-work from a sender it
 * has never seen before, the challenge prefix is bound to a
 * specific envelope so a solved token cannot be transplanted to
 * another sender, recipient, or postmark id.
 *
 * The bound prefix shape is:
 *
 *   prefix = random_bytes(16) || SHA-256(
 *       "SEMP-FIRST-CONTACT-V1:" ||
 *       sender_domain || 0x00 ||
 *       recipient_address || 0x00 ||
 *       postmark_id
 *   )
 *
 * The leading random nonce supplies freshness; the trailing
 * SHA-256 binds the prefix to the (sender, recipient, envelope)
 * triple. NUL is forbidden in all three field types by ENVELOPE.md
 * §2.2 and §2.3, so the field separators are unambiguous.
 *
 * The PoW algorithm itself (computeChallengeSolution +
 * verifyChallengeSolution) lives in {@link "./pow"}.
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

/** Domain-separation tag prefixed before the binding hash. */
export const FirstContactBindingTag = "SEMP-FIRST-CONTACT-V1:";

/** NUL field separator (0x00). */
export const FirstContactFieldSep = 0x00;

/** SHA-256 output size. */
export const FirstContactBindingHashSize = 32;

/** Random nonce length per §2.2a.3. */
export const FirstContactPrefixRandBytes = 16;

/**
 * Compute the bound prefix bytes. Returns the raw 48-byte buffer
 * (16-byte random || 32-byte SHA-256). Callers typically
 * base64-encode this for transmission.
 *
 * `rand` is an optional injectable random source (defaults to
 * `globalThis.crypto.getRandomValues`).
 */
export function computeFirstContactPrefix(
  senderDomain: string,
  recipientAddress: string,
  postmarkId: string,
  rand: (n: number) => Uint8Array = defaultRand,
): Uint8Array {
  if (senderDomain === "" || recipientAddress === "" || postmarkId === "") {
    throw new Error(
      "handshake: first-contact prefix requires sender_domain, recipient_address, and postmark_id",
    );
  }
  const random = rand(FirstContactPrefixRandBytes);
  if (random.length !== FirstContactPrefixRandBytes) {
    throw new Error("handshake: first-contact random source returned wrong length");
  }
  const hash = firstContactBindingHash(senderDomain, recipientAddress, postmarkId);
  const out = new Uint8Array(FirstContactPrefixRandBytes + FirstContactBindingHashSize);
  out.set(random, 0);
  out.set(hash, FirstContactPrefixRandBytes);
  return out;
}

/**
 * Verify that `prefix` binds to the supplied `(senderDomain,
 * recipientAddress, postmarkId)` triple. Returns true when the
 * trailing 32 bytes of the prefix are SHA-256 of the canonical
 * binding input.
 *
 * Does NOT verify the PoW solution itself - pair with
 * `verifyChallengeSolution` from {@link "./pow"} for a full check.
 */
export function verifyFirstContactBinding(
  prefix: Uint8Array,
  senderDomain: string,
  recipientAddress: string,
  postmarkId: string,
): boolean {
  if (senderDomain === "" || recipientAddress === "" || postmarkId === "") {
    return false;
  }
  if (
    prefix.length < FirstContactPrefixRandBytes + FirstContactBindingHashSize
  ) {
    return false;
  }
  const want = firstContactBindingHash(senderDomain, recipientAddress, postmarkId);
  const got = prefix.subarray(prefix.length - FirstContactBindingHashSize);
  // Constant-time compare on equal-length buffers.
  let diff = 0;
  for (let i = 0; i < want.length; i++) {
    diff |= (want[i] ?? 0) ^ (got[i] ?? 0);
  }
  return diff === 0;
}

/** Decode a base64-encoded prefix back to raw bytes. */
export function decodeFirstContactPrefix(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * Domain-separated, NUL-bounded SHA-256 over the binding triple per
 * §2.2a.3.
 */
function firstContactBindingHash(
  senderDomain: string,
  recipientAddress: string,
  postmarkId: string,
): Uint8Array {
  const enc = new TextEncoder();
  const tag = enc.encode(FirstContactBindingTag);
  const sd = enc.encode(senderDomain);
  const ra = enc.encode(recipientAddress);
  const pid = enc.encode(postmarkId);
  const buf = new Uint8Array(tag.length + sd.length + 1 + ra.length + 1 + pid.length);
  let off = 0;
  buf.set(tag, off);
  off += tag.length;
  buf.set(sd, off);
  off += sd.length;
  buf[off++] = FirstContactFieldSep;
  buf.set(ra, off);
  off += ra.length;
  buf[off++] = FirstContactFieldSep;
  buf.set(pid, off);
  return sha256(buf);
}

function defaultRand(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}
