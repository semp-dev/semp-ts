/**
 * Seal-layer key wrap per ENVELOPE.md §4.4.1.
 *
 * The wrap protects a fresh symmetric key (K_brief or K_enclosure)
 * for one recipient. The construction is HPKE-Base style:
 *
 *   1. KEM: encapsulate against the recipient's public key. For
 *      X25519 the encapsulation generates a fresh ephemeral and
 *      computes ECDH; for Kyber768+X25519 hybrid both halves run
 *      in parallel.
 *   2. KDF: HKDF-SHA-512 over the shared secret with salt
 *      `kemCt || recipientPub` and info "SEMP-v1-wrap".
 *   3. AEAD: zero nonce, recipient pub as AAD, plaintext = the
 *      symmetric key being wrapped. The zero nonce is safe because
 *      the wrap key is unique per call (fresh ephemeral feeds
 *      into the KDF).
 *
 * Output: `kemCt || aeadCt`, base64-encoded.
 *
 * @module
 */

import {
  type AEADAlgorithm,
  aeadOpen,
  hybridDecapsulate,
  newHKDFSHA512,
  x25519Agree,
} from "../crypto/index.js";

/** HKDF info context for the wrap-key expansion. */
export const WrapInfo = "SEMP-v1-wrap";

/** Algorithm suite identifiers used on the wire. */
export type Suite = "x25519-chacha20-poly1305" | "pq-kyber768-x25519";

/**
 * Unwrap a wrapped symmetric key per §4.4.1. Reverses the wrap
 * computation: split kemCt from aeadCt by AEAD-overhead size,
 * decapsulate, derive wrap_key, AEAD-open.
 *
 * @param suite negotiated suite that produced the wrap.
 * @param recipientPrivateKey for X25519: 32 bytes; for hybrid:
 *   2432 bytes (kyberPriv || x25519Priv per §4.4.1).
 * @param recipientPublicKey for X25519: 32 bytes; for hybrid:
 *   1216 bytes (kyberPub || x25519Pub per §4.4.1).
 * @param wrappedB64 base64 of (kemCt || aeadCt).
 */
export function unwrap(
  suite: Suite,
  recipientPrivateKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  wrappedB64: string,
): Uint8Array {
  if (recipientPrivateKey.length === 0) {
    throw new Error("seal: empty recipient private key");
  }
  if (recipientPublicKey.length === 0) {
    throw new Error("seal: empty recipient public key");
  }
  const raw = base64Decode(wrappedB64);

  const aead = suiteAEAD(suite);
  // For both currently defined suites the wrapped symmetric key
  // is 32 bytes (the AEAD key length); AEAD overhead is 16 bytes
  // (Poly1305 tag); so aead_ct length is 48 bytes regardless of
  // the K being wrapped.
  const aeadCTLen = 32 + 16;
  if (raw.length < aeadCTLen) {
    throw new Error("seal: wrapped key truncated");
  }
  const kemCTLen = raw.length - aeadCTLen;
  const kemCT = raw.slice(0, kemCTLen);
  const aeadCT = raw.slice(kemCTLen);

  const sharedSecret = decapsulate(suite, kemCT, recipientPrivateKey);

  // KDF: salt = kemCt || recipientPublicKey, info = SEMP-v1-wrap.
  const salt = concat(kemCT, recipientPublicKey);
  const kdf = newHKDFSHA512();
  const prk = kdf.extract(salt, sharedSecret);
  const wrapKey = kdf.expand(prk, new TextEncoder().encode(WrapInfo), 32);

  // AEAD: zero nonce, recipientPublicKey as AAD. The seal AEAD is
  // ChaCha20-Poly1305 (12-byte nonce) regardless of suite — only
  // the KEM is post-quantum on the PQ side. The `suite`-derived
  // `aead` here is unused but kept for signature parity.
  void aead;
  const nonce = new Uint8Array(12);
  return aeadOpen("chacha20-poly1305", wrapKey, nonce, aeadCT, recipientPublicKey);
}

function decapsulate(
  suite: Suite,
  kemCT: Uint8Array,
  recipientPrivateKey: Uint8Array,
): Uint8Array {
  switch (suite) {
    case "x25519-chacha20-poly1305":
      // KEM ciphertext is the sender's ephemeral public key (32B);
      // shared secret = ECDH(localPriv, ephPub).
      if (kemCT.length !== 32) {
        throw new Error(
          `seal: x25519 kemCT must be 32 bytes, got ${kemCT.length}`,
        );
      }
      return x25519Agree(recipientPrivateKey, kemCT);
    case "pq-kyber768-x25519":
      return hybridDecapsulate(kemCT, recipientPrivateKey);
  }
}

function suiteAEAD(suite: Suite): AEADAlgorithm {
  switch (suite) {
    case "x25519-chacha20-poly1305":
      return "chacha20-poly1305";
    case "pq-kyber768-x25519":
      return "xchacha20-poly1305";
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
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
