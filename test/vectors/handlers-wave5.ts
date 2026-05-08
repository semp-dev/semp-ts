/**
 * Wave 5 vectors-runner handlers: AEAD + KEM + KDF round-trips.
 *
 * Categories:
 *   - account-recovery   (1) Argon2id + XChaCha20-Poly1305 + Ed25519
 *   - large-attachment   (4) HKDF-Expand + ChaCha20/XChaCha20-Poly1305 +
 *                            canonical AAD + tampered cases
 *   - seal-roundtrip     (5) HPKE-Base baseline + PQ Kyber+X25519
 *                            (verify-only via Unwrap)
 *   - envelope-roundtrip (2) full envelope flow: seal verify, MAC
 *                            verify, brief AEAD round-trip,
 *                            enclosure AEAD round-trip,
 *                            sender_signature verify
 *
 * @module
 */

import { expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";

import { marshal as canonicalMarshal } from "../../src/canonical/index.js";
import { verify as ed25519Verify } from "../../src/keys/index.js";
import {
  type AEADAlgorithm,
  aeadOpen,
  argon2idKDF,
  computeMAC,
  hybridPrivateKeyFromKyberAndX25519,
  kyber768KeyPairFromSeed,
  newHKDFSHA512,
} from "../../src/crypto/index.js";
import { canonicalEnvelopeBytes } from "../../src/envelope/index.js";
import { unwrap as sealUnwrap } from "../../src/seal/index.js";
import {
  type VectorEntry,
  bytesEqual,
  decodeBase64,
  decodeHex,
  encodeHex,
  getBool,
  getField,
  getInt,
  getString,
  isRecord,
} from "./helpers.js";
import { verifySingleSignedDoc } from "./handlers-signed.js";

// ---------------------------------------------------------------------------
// account-recovery (RECOVERY.md §2)

export function handleAccountRecovery(entry: VectorEntry): void {
  if (entry.id !== "recovery-bundle-roundtrip") {
    throw new Error(`account-recovery: unknown sub-vector ${entry.id}`);
  }
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }

  const secret = new TextEncoder().encode(getString(entry.inputs, "recovery_secret_utf8"));
  const salt = decodeHex(getString(entry.inputs, "kdf_salt_hex"));
  const memKB = getInt(entry.inputs, "kdf_memory_kb");
  const iters = getInt(entry.inputs, "kdf_iterations");
  const par = getInt(entry.inputs, "kdf_parallelism");

  const bundleKey = argon2idKDF(secret, salt, memKB, iters, par, 32);

  const bundle = entry.expected.signed_bundle_json;
  if (!isRecord(bundle)) {
    throw new Error(`${entry.id}: signed_bundle_json missing`);
  }
  const ctB64 = bundle.encrypted_payload;
  const nonceB64 = bundle.payload_nonce;
  if (typeof ctB64 !== "string" || typeof nonceB64 !== "string") {
    throw new Error(`${entry.id}: encrypted_payload or payload_nonce missing`);
  }
  const ct = decodeBase64(ctB64);
  const nonce = decodeBase64(nonceB64);

  // XChaCha20-Poly1305, empty AAD per §2.4.
  const pt = aeadOpen("xchacha20-poly1305", bundleKey, nonce, ct, new Uint8Array(0));

  const wantPlaintextRaw = getField(entry.inputs, "payload_pre_encrypt_json");
  // Compare structural content; field order on the wire need not
  // match the pre-encrypt order, but the structural content must.
  const gotJSON = JSON.parse(new TextDecoder().decode(pt)) as unknown;
  expect(canonicalize(gotJSON)).toBe(canonicalize(wantPlaintextRaw));

  // KDF re-determinism: re-deriving from the same inputs gives
  // the same K_bundle.
  const bundleKey2 = argon2idKDF(secret, salt, memKB, iters, par, 32);
  expect(bytesEqual(bundleKey, bundleKey2)).toBe(
    getBool(entry.expected, "kdf_redeterms_K_bundle"),
  );

  // Bundle signature: SEMP-RECOVERY-BUNDLE: prefix.
  const identityPub = decodeHex(getString(entry.inputs, "identity_pub_hex"));
  const { ok } = verifySingleSignedDoc({
    signedJSON: bundle,
    signaturePath: "signature.value",
    publicKey: identityPub,
    prefix: "SEMP-RECOVERY-BUNDLE:",
  });
  expect(ok).toBe(getBool(entry.expected, "signature_verifies"));
}

function canonicalize(v: unknown): string {
  return new TextDecoder().decode(canonicalMarshal(v));
}

// ---------------------------------------------------------------------------
// large-attachment (ATTACHMENTS.md §3)
//
// The AAD is the canonical JSON of the item with ciphertext_hash,
// aead_nonce, and extensions blanked. Routing through the canonical
// marshaler (alphabetical key sort) is required for cross-language
// interop — semp-go's struct-order json.Marshal was VR-5 in Phase 2.

export function handleLargeAttachment(entry: VectorEntry): void {
  switch (entry.id) {
    case "large-attachment-baseline-valid":
    case "large-attachment-pq-valid":
      handleLargeAttachmentValid(entry);
      break;
    case "large-attachment-tampered-metadata":
      handleLargeAttachmentTamperedMeta(entry);
      break;
    case "large-attachment-tampered-ciphertext":
      handleLargeAttachmentTamperedCT(entry);
      break;
    default:
      throw new Error(`large-attachment: unknown sub-vector ${entry.id}`);
  }
}

function attachmentAAD(item: unknown): Uint8Array {
  if (!isRecord(item)) {
    throw new Error("attachment AAD: item is not an object");
  }
  const clone = { ...item };
  clone.ciphertext_hash = "";
  clone.aead_nonce = "";
  clone.extensions = {};
  return canonicalMarshal(clone);
}

function deriveAttachmentKey(
  kEnclosure: Uint8Array,
  attachmentId: string,
): Uint8Array {
  // ATTACHMENTS.md §3.1: K_attachment = HKDF-Expand(prk = kEnclosure,
  // info = "semp-attachment:" || attachmentId, L = 32). The HKDF here
  // is HKDF-SHA-512.
  const info = new TextEncoder().encode(`semp-attachment:${attachmentId}`);
  // Use Expand directly via @noble/hashes/hkdf — pass the
  // already-extracted PRK (which is K_enclosure here).
  return expandHKDFSHA512(kEnclosure, info, 32);
}

function expandHKDFSHA512(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  // Per ATTACHMENTS.md §3.1 the attachment derivation runs
  // HKDF-Expand directly over K_enclosure (32 bytes) as the PRK.
  // RFC 5869 §2.3 lets Expand accept a PRK shorter than HashLen
  // when the caller asserts the input has full entropy; @noble's
  // strict expand() rejects PRK < HashLen, so we run the
  // T(1) || T(2) || ... loop explicitly with HMAC-SHA-512.
  const hmacSize = 64;
  const N = Math.ceil(length / hmacSize);
  if (N > 255) {
    throw new Error("HKDF-Expand: requested length too large");
  }
  let prev = new Uint8Array(0);
  const out = new Uint8Array(length);
  let written = 0;
  for (let i = 1; i <= N; i++) {
    const buf = new Uint8Array(prev.length + info.length + 1);
    buf.set(prev, 0);
    buf.set(info, prev.length);
    buf[prev.length + info.length] = i;
    const t = hmacSHA512(prk, buf);
    const take = Math.min(hmacSize, length - written);
    out.set(t.slice(0, take), written);
    written += take;
    prev = t;
  }
  return out;
}

function hmacSHA512(key: Uint8Array, msg: Uint8Array): Uint8Array {
  // Inline HMAC-SHA-512 to avoid threading another @noble import.
  const blockSize = 128;
  const hashLen = 64;
  const k = key.length > blockSize ? sha512(key) : key;
  const padded = new Uint8Array(blockSize);
  padded.set(k, 0);
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = padded[i]! ^ 0x36;
    opad[i] = padded[i]! ^ 0x5c;
  }
  const inner = new Uint8Array(blockSize + msg.length);
  inner.set(ipad, 0);
  inner.set(msg, blockSize);
  const innerHash = sha512(inner);
  const outer = new Uint8Array(blockSize + hashLen);
  outer.set(opad, 0);
  outer.set(innerHash, blockSize);
  return sha512(outer);
}

function handleLargeAttachmentValid(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const kEnc = decodeHex(getString(entry.inputs, "K_enclosure_hex"));
  const attachmentId = getString(entry.inputs, "attachment_id");
  const plaintext = decodeHex(getString(entry.inputs, "plaintext_hex"));
  const nonce = decodeHex(getString(entry.inputs, "aead_nonce_hex"));
  const template = entry.inputs.item_pre_encrypt_template;
  if (!isRecord(template)) {
    throw new Error(`${entry.id}: item_pre_encrypt_template missing`);
  }

  const kAttachment = deriveAttachmentKey(kEnc, attachmentId);
  const aad = attachmentAAD(template);
  const algo = getString(template, "aead_algorithm") as AEADAlgorithm;

  const wantCT = decodeHex(getString(entry.expected, "ciphertext_at_url_hex"));
  // Round-trip via open: AEAD.Open MUST recover the plaintext from
  // the pinned ciphertext under (K, nonce, AAD).
  const recovered = aeadOpen(algo, kAttachment, nonce, wantCT, aad);
  expect(bytesEqual(recovered, plaintext)).toBe(true);

  // ciphertext_hash sanity check: SHA-256(aead_ct).
  const final = entry.expected.item_final_json;
  if (isRecord(final)) {
    const expect_hash = `sha256:${encodeHex(sha256(wantCT))}`;
    expect(final.ciphertext_hash).toBe(expect_hash);
  }
}

function handleLargeAttachmentTamperedMeta(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const kAtt = decodeHex(getString(entry.inputs, "K_attachment_hex"));
  const nonce = decodeHex(getString(entry.inputs, "aead_nonce_hex"));
  const ct = decodeHex(getString(entry.inputs, "ciphertext_at_url_hex"));
  const tamperedItem = entry.inputs.tampered_item_json;
  if (!isRecord(tamperedItem)) {
    throw new Error(`${entry.id}: tampered_item_json missing`);
  }
  const algo = getString(tamperedItem, "aead_algorithm") as AEADAlgorithm;
  const aad = attachmentAAD(tamperedItem);
  let decrypts = false;
  try {
    aeadOpen(algo, kAtt, nonce, ct, aad);
    decrypts = true;
  } catch {
    decrypts = false;
  }
  expect(decrypts).toBe(getBool(entry.expected, "decryption_succeeds"));
}

function handleLargeAttachmentTamperedCT(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const kAtt = decodeHex(getString(entry.inputs, "K_attachment_hex"));
  const nonce = decodeHex(getString(entry.inputs, "aead_nonce_hex"));
  const tamperedCT = decodeHex(getString(entry.inputs, "tampered_ciphertext_hex"));
  const item = entry.inputs.item_json;
  if (!isRecord(item)) {
    throw new Error(`${entry.id}: item_json missing`);
  }
  const algo = getString(item, "aead_algorithm") as AEADAlgorithm;
  const aad = attachmentAAD(item);

  // Hash mismatch: SHA-256(tampered_ct) != item.ciphertext_hash.
  const recomputed = `sha256:${encodeHex(sha256(tamperedCT))}`;
  const hashMatches = recomputed === item.ciphertext_hash;
  expect(hashMatches).toBe(getBool(entry.expected, "ciphertext_hash_matches"));

  // AEAD also fails (tag mismatch).
  let decrypts = false;
  try {
    aeadOpen(algo, kAtt, nonce, tamperedCT, aad);
    decrypts = true;
  } catch {
    decrypts = false;
  }
  expect(decrypts).toBe(getBool(entry.expected, "aead_decryption_succeeds"));
}

// ---------------------------------------------------------------------------
// seal-roundtrip
//
// Each vector pins the wrapped bytes plus all the recipient's
// keying material. We exercise the receive-side path: feed
// wrapped_b64 to seal.unwrap and assert K is recovered byte-for-byte.

export function handleSealRoundtrip(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const suiteStr = getString(entry.inputs, "suite");
  const wrappedB64 = getString(entry.expected, "wrapped_b64");
  const wantK = decodeHex(getString(entry.inputs, "symmetric_key_hex"));

  let priv: Uint8Array;
  let pub: Uint8Array;
  switch (suiteStr) {
    case "x25519-chacha20-poly1305":
      priv = decodeHex(getString(entry.inputs, "recipient_private_key_hex"));
      pub = decodeHex(getString(entry.inputs, "recipient_public_key_hex"));
      break;
    case "pq-kyber768-x25519": {
      const d = decodeHex(getString(entry.inputs, "recipient_kyber_keygen_d_hex"));
      const z = decodeHex(getString(entry.inputs, "recipient_kyber_keygen_z_hex"));
      const xPriv = decodeHex(getString(entry.inputs, "recipient_x25519_private_key_hex"));
      const seed = new Uint8Array(64);
      seed.set(d, 0);
      seed.set(z, 32);
      const { secretKey: kyberPriv } = kyber768KeyPairFromSeed(seed);
      priv = hybridPrivateKeyFromKyberAndX25519(xPriv, kyberPriv);
      pub = decodeHex(getString(entry.inputs, "recipient_hybrid_public_key_hex"));
      break;
    }
    default:
      throw new Error(`seal-roundtrip: unknown suite ${suiteStr}`);
  }

  const got = sealUnwrap(suiteStr, priv, pub, wrappedB64);
  expect(bytesEqual(got, wantK), `${entry.id}: unwrap recovered K`).toBe(true);
  expect(getBool(entry.expected, "round_trip_recovers_K")).toBe(true);
}

// ---------------------------------------------------------------------------
// envelope-roundtrip
//
// Receive-side check on a pinned envelope:
//   1. seal.signature verifies under sender_domain_signing_pub.
//   2. seal.session_mac verifies under K_env_mac.
//   3. Unwrap recipient_client's brief recipient -> K_brief.
//      AEAD-decrypt envelope.brief (base64(nonce || aead_ct) per
//      §7.1.1) with postmark.id as AAD. Round-trip recovers
//      brief_pre_encrypt_json.
//   4. Unwrap recipient_client's enclosure recipient -> K_enclosure.
//      Same AEAD flow.
//   5. sender_signature on the decrypted enclosure verifies under
//      sender_identity_pub.

export function handleEnvelopeRoundtrip(entry: VectorEntry): void {
  switch (entry.id) {
    case "envelope-roundtrip-baseline-single-recipient":
      // Both suites use ChaCha20-Poly1305 for brief/enclosure
      // per ENVELOPE.md §7.1.1; only the KEM differs.
      runEnvelopeRoundtrip(entry, "x25519-chacha20-poly1305", "chacha20-poly1305");
      break;
    case "envelope-roundtrip-pq-single-recipient":
      runEnvelopeRoundtrip(entry, "pq-kyber768-x25519", "chacha20-poly1305");
      break;
    default:
      throw new Error(`envelope-roundtrip: unknown sub-vector ${entry.id}`);
  }
}

function runEnvelopeRoundtrip(
  entry: VectorEntry,
  suite: "x25519-chacha20-poly1305" | "pq-kyber768-x25519",
  aead: AEADAlgorithm,
): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const env = entry.expected.envelope_json;
  if (!isRecord(env)) {
    throw new Error(`${entry.id}: envelope_json missing`);
  }
  const canonicalEnv = canonicalEnvelopeBytes(env);

  // Step 1: seal.signature.
  const senderPub = decodeHex(getString(entry.inputs, "sender_domain_signing_pub_hex"));
  const seal = env.seal;
  if (!isRecord(seal)) {
    throw new Error(`${entry.id}: seal missing`);
  }
  const sealSigB64 = seal.signature;
  if (typeof sealSigB64 !== "string") {
    throw new Error(`${entry.id}: seal.signature missing`);
  }
  const sealSig = decodeBase64(sealSigB64);
  const signingInput = concat(new TextEncoder().encode("SEMP-ENVELOPE:"), canonicalEnv);
  const sealOK = ed25519Verify(senderPub, sealSig, signingInput);
  expect(sealOK).toBe(getBool(entry.expected, "seal_signature_verifies"));

  // Step 2: session_mac.
  const kEnvMac = decodeHex(getString(entry.inputs, "K_env_mac_hex"));
  const wantMAC = computeMAC(kEnvMac, canonicalEnv);
  const sessMacB64 = seal.session_mac;
  if (typeof sessMacB64 !== "string") {
    throw new Error(`${entry.id}: seal.session_mac missing`);
  }
  const gotMAC = decodeBase64(sessMacB64);
  expect(bytesEqual(wantMAC, gotMAC)).toBe(
    getBool(entry.expected, "session_mac_verifies"),
  );

  // Step 3: brief AEAD round-trip via recipient_client unwrap.
  const clientFP = getString(entry.inputs, "recipient_client_key_id");
  const { priv: clientPriv, pub: clientPub } = recipientKeysForSuite(entry, suite);

  const briefRecipients = seal.brief_recipients;
  if (!isRecord(briefRecipients) || typeof briefRecipients[clientFP] !== "string") {
    throw new Error(`${entry.id}: client missing from brief_recipients`);
  }
  const briefWrapped = briefRecipients[clientFP] as string;
  const kBrief = sealUnwrap(suite, clientPriv, clientPub, briefWrapped);

  const briefNonce = decodeHex(getString(entry.inputs, "brief_aead_nonce_hex"));
  const briefBlob = decodeBase64(getString(env, "brief"));
  if (briefBlob.length < briefNonce.length) {
    throw new Error(`${entry.id}: brief blob too short`);
  }
  const briefNonceFromWire = briefBlob.slice(0, briefNonce.length);
  const briefCT = briefBlob.slice(briefNonce.length);
  expect(bytesEqual(briefNonceFromWire, briefNonce)).toBe(true);

  const postmarkID = getString(entry.inputs, "postmark_id");
  const briefPT = aeadOpen(aead, kBrief, briefNonce, briefCT, new TextEncoder().encode(postmarkID));
  const wantBrief = entry.inputs.brief_pre_encrypt_json;
  expect(canonicalize(JSON.parse(new TextDecoder().decode(briefPT)))).toBe(
    canonicalize(wantBrief),
  );
  expect(getBool(entry.expected, "round_trip_recovers_brief")).toBe(true);

  // Step 4: enclosure AEAD round-trip.
  const enclRecipients = seal.enclosure_recipients;
  if (!isRecord(enclRecipients) || typeof enclRecipients[clientFP] !== "string") {
    throw new Error(`${entry.id}: client missing from enclosure_recipients`);
  }
  const enclWrapped = enclRecipients[clientFP] as string;
  const kEncl = sealUnwrap(suite, clientPriv, clientPub, enclWrapped);

  const enclNonce = decodeHex(getString(entry.inputs, "enclosure_aead_nonce_hex"));
  const enclBlob = decodeBase64(getString(env, "enclosure"));
  if (enclBlob.length < enclNonce.length) {
    throw new Error(`${entry.id}: enclosure blob too short`);
  }
  const enclNonceFromWire = enclBlob.slice(0, enclNonce.length);
  const enclCT = enclBlob.slice(enclNonce.length);
  expect(bytesEqual(enclNonceFromWire, enclNonce)).toBe(true);
  const enclPT = aeadOpen(aead, kEncl, enclNonce, enclCT, new TextEncoder().encode(postmarkID));
  expect(getBool(entry.expected, "round_trip_recovers_enclosure")).toBe(true);

  // Step 5: sender_signature on the decrypted enclosure.
  const enclosure = JSON.parse(new TextDecoder().decode(enclPT)) as unknown;
  if (!isRecord(enclosure)) {
    throw new Error(`${entry.id}: decrypted enclosure not an object`);
  }
  const identityPub = decodeHex(getString(entry.inputs, "sender_identity_pub_hex"));
  const sigRes = verifySingleSignedDoc({
    signedJSON: enclosure,
    signaturePath: "sender_signature.value",
    publicKey: identityPub,
    prefix: "SEMP-ENCLOSURE-SENDER:",
  });
  expect(sigRes.ok).toBe(getBool(entry.expected, "sender_signature_verifies"));
}

function recipientKeysForSuite(
  entry: VectorEntry,
  suite: "x25519-chacha20-poly1305" | "pq-kyber768-x25519",
): { priv: Uint8Array; pub: Uint8Array } {
  if (!isRecord(entry.inputs)) {
    throw new Error("envelope-roundtrip: inputs missing");
  }
  if (suite === "x25519-chacha20-poly1305") {
    return {
      priv: decodeHex(getString(entry.inputs, "recipient_client_priv_hex")),
      pub: decodeHex(getString(entry.inputs, "recipient_client_pub_hex")),
    };
  }
  const d = decodeHex(getString(entry.inputs, "recipient_client_kyber_keygen_d_hex"));
  const z = decodeHex(getString(entry.inputs, "recipient_client_kyber_keygen_z_hex"));
  const xPriv = decodeHex(getString(entry.inputs, "recipient_client_x25519_priv_hex"));
  const seed = new Uint8Array(64);
  seed.set(d, 0);
  seed.set(z, 32);
  const { secretKey: kyberPriv } = kyber768KeyPairFromSeed(seed);
  return {
    priv: hybridPrivateKeyFromKyberAndX25519(xPriv, kyberPriv),
    pub: decodeHex(getString(entry.inputs, "recipient_client_pub_hex")),
  };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// Quiet unused-import lint: kept for future Wave 6 dispatches.
void hkdf;
void sha512;
