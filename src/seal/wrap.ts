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
  aeadSeal,
  hybridDecapsulate,
  Kyber768CiphertextSize,
  Kyber768PublicKeySize,
  kyber768EncapsulateDeterministic,
  newHKDFSHA512,
  x25519Agree,
  x25519PublicKey,
  X25519Size,
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

/**
 * Wrap `symmetricKey` for the given recipient under the negotiated
 * suite. Production code path: uses the platform CSPRNG to generate
 * a fresh ephemeral every call, which is what the §4.4.1 wrap
 * construction requires — wrap-key uniqueness is what makes the
 * zero-nonce AEAD safe.
 *
 * For deterministic byte-level reproducibility (vectors, audits),
 * use {@link wrapWithRandomness} instead and pass pinned
 * ephemeral inputs.
 */
export function wrap(
  suite: Suite,
  recipientPublicKey: Uint8Array,
  symmetricKey: Uint8Array,
): string {
  switch (suite) {
    case "x25519-chacha20-poly1305": {
      const ephPriv = randomBytes(X25519Size);
      return wrapWithRandomness(suite, recipientPublicKey, symmetricKey, {
        ephemeralX25519Priv: ephPriv,
      });
    }
    case "pq-kyber768-x25519": {
      const ephPriv = randomBytes(X25519Size);
      const kyberM = randomBytes(32);
      return wrapWithRandomness(suite, recipientPublicKey, symmetricKey, {
        ephemeralX25519Priv: ephPriv,
        kyberEncapsRandomnessM: kyberM,
      });
    }
  }
}

/**
 * Inputs to a deterministic wrap. The fields a caller must pin to
 * reproduce the exact wrap bytes a previous run produced.
 */
export interface WrapRandomness {
  /** 32-byte X25519 ephemeral private key. Required for both suites. */
  ephemeralX25519Priv: Uint8Array;
  /**
   * 32-byte ML-KEM-768 encapsulation randomness (FIPS 203 `m`).
   * Required for the PQ suite, ignored for baseline.
   */
  kyberEncapsRandomnessM?: Uint8Array;
}

/**
 * Deterministic wrap for vector reproduction and audits. Production
 * code MUST use {@link wrap} (which sources fresh entropy) — a
 * deterministic wrap that leaks `ephemeralX25519Priv` reduces to
 * "the adversary has the wrap key". Exposed here only because
 * cross-language vectors pin these inputs.
 *
 * Returns base64(kemCt || aeadCt) per ENVELOPE.md §4.4.1.
 */
export function wrapWithRandomness(
  suite: Suite,
  recipientPublicKey: Uint8Array,
  symmetricKey: Uint8Array,
  randomness: WrapRandomness,
): string {
  const { kemCT, sharedSecret } = encapsulate(
    suite,
    recipientPublicKey,
    randomness,
  );

  // KDF: salt = kemCt || recipientPublicKey, info = SEMP-v1-wrap.
  const salt = concat(kemCT, recipientPublicKey);
  const kdf = newHKDFSHA512();
  const prk = kdf.extract(salt, sharedSecret);
  const wrapKey = kdf.expand(prk, new TextEncoder().encode(WrapInfo), 32);

  // AEAD: zero nonce, recipientPublicKey as AAD. Always
  // ChaCha20-Poly1305 (12-byte nonce) regardless of suite — only
  // the KEM is post-quantum on the PQ side.
  const nonce = new Uint8Array(12);
  const aeadCT = aeadSeal(
    "chacha20-poly1305",
    wrapKey,
    nonce,
    symmetricKey,
    recipientPublicKey,
  );

  const wrapped = concat(kemCT, aeadCT);
  return base64Encode(wrapped);
}

function encapsulate(
  suite: Suite,
  recipientPublicKey: Uint8Array,
  randomness: WrapRandomness,
): { kemCT: Uint8Array; sharedSecret: Uint8Array } {
  switch (suite) {
    case "x25519-chacha20-poly1305": {
      // X25519 KEM: kemCT is the sender's ephemeral pub; shared
      // secret is ECDH(ephPriv, recipientPub).
      if (recipientPublicKey.length !== X25519Size) {
        throw new Error(
          `seal: x25519 recipient pub must be ${X25519Size} bytes`,
        );
      }
      const ephPub = x25519PublicKey(randomness.ephemeralX25519Priv);
      const shared = x25519Agree(
        randomness.ephemeralX25519Priv,
        recipientPublicKey,
      );
      return { kemCT: ephPub, sharedSecret: shared };
    }
    case "pq-kyber768-x25519": {
      // Hybrid: kyber half (encapsulate against recipient kyber pub
      // with pinned m) + x25519 half (ephemeral ECDH against
      // recipient x25519 pub). Wire layout: kyberCt || x25519EphPub
      // for the ciphertext, kyberSS || x25519SS for the secret.
      if (randomness.kyberEncapsRandomnessM === undefined) {
        throw new Error("seal: PQ wrap requires kyberEncapsRandomnessM");
      }
      const kyberPub = recipientPublicKey.slice(0, Kyber768PublicKeySize);
      const xPub = recipientPublicKey.slice(Kyber768PublicKeySize);
      const { ciphertext: kyberCt, sharedSecret: kyberSS } =
        kyber768EncapsulateDeterministic(kyberPub, randomness.kyberEncapsRandomnessM);
      const xEphPub = x25519PublicKey(randomness.ephemeralX25519Priv);
      const xSS = x25519Agree(randomness.ephemeralX25519Priv, xPub);

      const kemCT = new Uint8Array(Kyber768CiphertextSize + X25519Size);
      kemCT.set(kyberCt, 0);
      kemCT.set(xEphPub, Kyber768CiphertextSize);

      const shared = new Uint8Array(64);
      shared.set(kyberSS, 0);
      shared.set(xSS, 32);

      return { kemCT, sharedSecret: shared };
    }
  }
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

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  // Web Crypto is available in Node >= 19 and every modern browser.
  globalThis.crypto.getRandomValues(out);
  return out;
}
