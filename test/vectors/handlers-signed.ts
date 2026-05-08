/**
 * Wave 3 vectors-runner handlers: single-signature documents.
 *
 * Every category in this file fits the same shape: take a signed
 * JSON object, blank a specific signature-value field path,
 * canonicalize per ENVELOPE.md §4.3, prepend a domain-separation
 * prefix, Ed25519-verify against the pinned public key. The
 * generic `verifySingleSignedDoc` helper plus a per-category
 * picker covers ten categories at modest cost — same pattern
 * semp-go landed in Wave 2A.
 *
 * Multi-signature chains (forwarding, migration) and round-trip
 * constructions (seal, envelope, large-attachment) are later
 * waves and live in their own files.
 *
 * @module
 */

import { expect } from "vitest";

import { marshal as canonicalMarshal } from "../../src/canonical/index.js";
import { confirmationHash, firstContactDigest } from "../../src/handshake/index.js";
import { verify as ed25519Verify } from "../../src/keys/index.js";
import {
  type VectorEntry,
  bytesEqual,
  decodeBase64,
  decodeHex,
  getBool,
  getField,
  getInt,
  getOptionalString,
  getString,
  isRecord,
} from "./helpers.js";
import {
  type KDF,
  computeMAC,
  deriveResumedSessionKeys,
  newHKDFSHA512,
} from "../../src/crypto/index.js";

/** Description of a single-signature document to verify. */
interface SignedDocSpec {
  /** The document AS PUBLISHED, with the signature value populated. */
  signedJSON: Record<string, unknown>;
  /** Dotted path to the signature value (e.g. "signature.value"). */
  signaturePath: string;
  /** 32-byte Ed25519 public key to verify under. */
  publicKey: Uint8Array;
  /** Domain-separation prefix from ENVELOPE.md §4.3. */
  prefix: string;
}

/**
 * Verify a single signed document. Deep-copies `signedJSON`,
 * navigates to the signature path, captures the value, sets it to
 * "", canonicalizes, and Ed25519-verifies the captured signature
 * over `prefix || canonical_blanked_bytes`.
 *
 * Returns the canonical-blanked bytes plus the verify outcome so
 * callers can also cross-check `intermediates.canonical_with_blanked_signature_utf8`
 * when the vector pins it.
 */
export function verifySingleSignedDoc(spec: SignedDocSpec): {
  canonicalBlanked: Uint8Array;
  ok: boolean;
} {
  const copy = deepCloneJSON(spec.signedJSON);
  const sigB64 = pluckAndBlankPath(copy, spec.signaturePath);
  const signature = decodeBase64(sigB64);
  const blanked = canonicalMarshal(copy);
  const signingInput = concat(new TextEncoder().encode(spec.prefix), blanked);
  const ok = ed25519Verify(spec.publicKey, signature, signingInput);
  return { canonicalBlanked: blanked, ok };
}

/**
 * Walk a dotted path (`signature.value`) through a record, capture
 * the leaf string value, and replace it with "" in place. Throws
 * if the path is malformed or the leaf is not a string.
 */
function pluckAndBlankPath(m: Record<string, unknown>, path: string): string {
  const parts = path.split(".");
  let cur: unknown = m;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!isRecord(cur)) {
      throw new Error(`path ${path}: segment ${parts.slice(0, i + 1).join(".")} is not an object`);
    }
    const next = cur[parts[i] ?? ""];
    if (next === undefined) {
      throw new Error(`path ${path}: missing segment ${parts[i]}`);
    }
    cur = next;
  }
  if (!isRecord(cur)) {
    throw new Error(`path ${path}: parent is not an object`);
  }
  const leafKey = parts[parts.length - 1];
  if (leafKey === undefined) {
    throw new Error(`path ${path}: empty`);
  }
  const leaf = cur[leafKey];
  if (typeof leaf !== "string") {
    throw new Error(`path ${path}: leaf is not a string`);
  }
  cur[leafKey] = "";
  return leaf;
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

// ---------------------------------------------------------------------------
// Picker helpers shared across categories

/**
 * Pull the published signed document out of `expected.<one of>`.
 * Different categories use different field names — we try the
 * common ones in order and fail with a clear error if none match.
 */
function signedDocFromExpected(entry: VectorEntry): Record<string, unknown> {
  if (!isRecord(entry.expected)) {
    throw new Error(`${entry.id}: expected is not an object`);
  }
  const candidates = [
    "signed_request_json",
    "signed_update_json",
    "signed_record_json",
    "signed_response_json",
    "signed_message_json",
    "signed_manifest_json",
    "signed_doc_json",
    "signed_receipt_json",
    "signed_bundle_json",
    "signed_enclosure_json",
    "outer_enclosure_json",
    "sth_signed_json",
  ];
  for (const k of candidates) {
    const v = entry.expected[k];
    if (isRecord(v)) {
      return v;
    }
  }
  throw new Error(`${entry.id}: no signed-doc field in expected`);
}

/**
 * Decode a hex-encoded public key from `inputs.<one of the
 * candidates>`. Throws if none match.
 */
function pubKeyFromInputs(entry: VectorEntry, ...candidates: string[]): Uint8Array {
  if (!isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: inputs not an object`);
  }
  for (const name of candidates) {
    const hex = entry.inputs[name];
    if (typeof hex === "string") {
      return decodeHex(hex);
    }
  }
  throw new Error(`${entry.id}: no pub key in inputs (tried ${candidates.join(", ")})`);
}

/** Optionally cross-check semp-ts's canonical bytes against intermediates.canonical_with_blanked_signature_utf8. */
function canonicalIntermediateMatches(entry: VectorEntry, blanked: Uint8Array): void {
  if (!isRecord(entry.intermediates)) {
    return;
  }
  const want = entry.intermediates.canonical_with_blanked_signature_utf8;
  if (typeof want !== "string") {
    return;
  }
  const got = new TextDecoder().decode(blanked);
  if (got !== want) {
    throw new Error(
      `${entry.id}: canonical-blanked mismatch\n  got  ${got}\n  want ${want}`,
    );
  }
}

/** Build a picker-bound handler from a static signature-path + prefix. */
function singleSignedDocHandler(
  pubKeyFields: string[],
  signaturePath: string,
  prefix: string,
): (entry: VectorEntry) => void {
  return (entry) => {
    const doc = signedDocFromExpected(entry);
    const pub = pubKeyFromInputs(entry, ...pubKeyFields);
    const { canonicalBlanked, ok } = verifySingleSignedDoc({
      signedJSON: doc,
      signaturePath,
      publicKey: pub,
      prefix,
    });
    canonicalIntermediateMatches(entry, canonicalBlanked);
    expect(ok, `${entry.id}: Ed25519 verify (${entry.spec_reference})`).toBe(true);
  };
}

// ---------------------------------------------------------------------------
// Per-category handlers (each is a single-signature document)

export const handleAccountClosure = singleSignedDocHandler(
  ["primary_device_pub_hex"],
  "signature.value",
  "SEMP-ACCOUNT-CLOSURE:",
);

export const handleConfigurationUpdate = singleSignedDocHandler(
  ["domain_pub_hex"],
  "signature.value",
  "SEMP-CONFIGURATION-UPDATE:",
);

export const handleUserPolicy = singleSignedDocHandler(
  ["user_identity_pub_hex", "device_pub_hex"],
  "signature.value",
  "SEMP-USER-POLICY:",
);

export const handleDiscoverySigned = singleSignedDocHandler(
  ["domain_pub_hex"],
  "signature.value",
  "SEMP-DISCOVERY:",
);

// ---------------------------------------------------------------------------
// handshake-messages: 5 entries with two shapes
//
//   canonical-only (init, confirm) — verify canonical bytes only
//   signed (response, accepted, rejected) — Ed25519 over server_signature
//
// session-resumption shares the same SEMP-HANDSHAKE: prefix and
// the same field path for the signed entries; canonical-only for
// the request; KDF for resume-key-derivation.

export function handleHandshakeMessages(entry: VectorEntry): void {
  switch (entry.id) {
    case "handshake-init-canonical":
    case "handshake-confirm-canonical":
      verifyCanonicalOnly(entry, "message_json");
      break;
    case "handshake-response-signed":
    case "handshake-accepted-signed":
    case "handshake-rejected-signed":
      handleHandshakeSigned(entry);
      break;
    default:
      throw new Error(`handshake-messages: unknown sub-vector ${entry.id}`);
  }
}

export function handleHandshakeMessagesPQ(entry: VectorEntry): void {
  switch (entry.id) {
    case "handshake-response-pq-signed":
    case "handshake-accepted-pq-signed":
      handleHandshakeSigned(entry);
      break;
    default:
      throw new Error(`handshake-messages-pq: unknown sub-vector ${entry.id}`);
  }
}

function handleHandshakeSigned(entry: VectorEntry): void {
  const doc = signedDocFromExpected(entry);
  const pub = pubKeyFromInputs(entry, "server_domain_pub_hex");
  const { canonicalBlanked, ok } = verifySingleSignedDoc({
    signedJSON: doc,
    signaturePath: "server_signature",
    publicKey: pub,
    prefix: "SEMP-HANDSHAKE:",
  });
  canonicalIntermediateMatches(entry, canonicalBlanked);
  expect(ok).toBe(true);
}

function verifyCanonicalOnly(entry: VectorEntry, inputField: string): void {
  if (!isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: inputs not an object`);
  }
  const msg = entry.inputs[inputField];
  if (msg === undefined) {
    return;
  }
  const got = canonicalMarshal(msg);
  if (!isRecord(entry.intermediates)) {
    return;
  }
  const want = entry.intermediates.canonical_utf8;
  if (typeof want === "string") {
    expect(new TextDecoder().decode(got)).toBe(want);
  }
}

export function handleSessionResumption(entry: VectorEntry): void {
  switch (entry.id) {
    case "resume-request-canonical":
      verifyCanonicalOnly(entry, "message_json");
      break;
    case "resume-accepted-signed":
      handleHandshakeSigned(entry);
      break;
    case "resume-key-derivation":
      handleResumeKeyDerivation(entry);
      break;
    default:
      throw new Error(`session-resumption: unknown sub-vector ${entry.id}`);
  }
}

function handleResumeKeyDerivation(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const ephSS = decodeHex(getString(entry.inputs, "ephemeral_shared_secret_hex"));
  const kRes = decodeHex(getString(entry.inputs, "K_resumption_hex"));
  const cNonce = decodeHex(getString(entry.inputs, "client_nonce_hex"));
  const sNonce = decodeHex(getString(entry.inputs, "server_nonce_hex"));

  const kdf: KDF = newHKDFSHA512();
  const keys = deriveResumedSessionKeys(kdf, ephSS, kRes, cNonce, sNonce);

  const ikm = concat(ephSS, kRes);
  const salt = concat(cNonce, sNonce);
  const prk = kdf.extract(salt, ikm);
  const wantPRK = decodeHex(getString(entry.expected, "prk_resume_hex"));
  expect(toHex(prk)).toBe(toHex(wantPRK));

  const expectedKeys = getField(entry.expected, "keys");
  if (!isRecord(expectedKeys)) {
    throw new Error(`${entry.id}: expected.keys missing`);
  }
  expect(toHex(keys.encC2S)).toBe(getString(expectedKeys, "K_enc_c2s_hex"));
  expect(toHex(keys.encS2C)).toBe(getString(expectedKeys, "K_enc_s2c_hex"));
  expect(toHex(keys.macC2S)).toBe(getString(expectedKeys, "K_mac_c2s_hex"));
  expect(toHex(keys.macS2C)).toBe(getString(expectedKeys, "K_mac_s2c_hex"));
  expect(toHex(keys.envMAC)).toBe(getString(expectedKeys, "K_env_mac_hex"));
}

function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += (b[i] ?? 0).toString(16).padStart(2, "0");
  }
  return s;
}

// ---------------------------------------------------------------------------
// recovery-shamir
//
// Three entries: shamir-split-and-combine (GF(256) interpolation),
// shamir-recovery-set-manifest-signed (Ed25519, signature.value),
// shamir-share-record-signed (multiple records each with their own
// device_signature.value).

export function handleRecoveryShamir(entry: VectorEntry): void {
  switch (entry.id) {
    case "shamir-recovery-set-manifest-signed": {
      const doc = signedDocFromExpected(entry);
      const pub = pubKeyFromInputs(entry, "user_pub_hex");
      const { canonicalBlanked, ok } = verifySingleSignedDoc({
        signedJSON: doc,
        signaturePath: "signature.value",
        publicKey: pub,
        prefix: "SEMP-RECOVERY-MANIFEST:",
      });
      canonicalIntermediateMatches(entry, canonicalBlanked);
      expect(ok).toBe(true);
      break;
    }
    case "shamir-share-record-signed":
      handleShamirShareRecords(entry);
      break;
    case "shamir-split-and-combine":
      handleShamirRoundTrip(entry);
      break;
    default:
      throw new Error(`recovery-shamir: unknown sub-vector ${entry.id}`);
  }
}

function handleShamirShareRecords(entry: VectorEntry): void {
  if (!isRecord(entry.expected) || !isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: missing expected or inputs`);
  }
  const records = entry.expected.signed_share_records_json;
  if (!Array.isArray(records)) {
    throw new Error(`${entry.id}: signed_share_records_json not an array`);
  }
  const pubsHexRaw = entry.inputs.device_pubs_hex;
  if (!Array.isArray(pubsHexRaw)) {
    throw new Error(`${entry.id}: device_pubs_hex not an array`);
  }
  expect(records.length).toBe(pubsHexRaw.length);
  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    const pubHex = pubsHexRaw[i];
    if (!isRecord(rec) || typeof pubHex !== "string") {
      throw new Error(`${entry.id}: malformed record[${i}]`);
    }
    const { ok } = verifySingleSignedDoc({
      signedJSON: rec,
      signaturePath: "device_signature.value",
      publicKey: decodeHex(pubHex),
      prefix: "SEMP-RECOVERY-SHARE:",
    });
    expect(ok, `${entry.id}: share[${i}]`).toBe(true);
  }
}

// ---------------------------------------------------------------------------
// Shamir GF(256) split + Lagrange combine (RECOVERY.md §5.1, §5.4)

function gf256Mul(a: number, b: number): number {
  let p = 0;
  let aa = a & 0xff;
  let bb = b & 0xff;
  for (let i = 0; i < 8; i++) {
    if ((bb & 1) !== 0) {
      p ^= aa;
    }
    const hi = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hi !== 0) {
      aa ^= 0x1b; // low byte of 0x11b (AES irreducible polynomial)
    }
    bb >>= 1;
  }
  return p & 0xff;
}

function gf256Pow(base: number, exp: number): number {
  let result = 1;
  let bb = base & 0xff;
  let ee = exp;
  while (ee > 0) {
    if ((ee & 1) === 1) {
      result = gf256Mul(result, bb);
    }
    bb = gf256Mul(bb, bb);
    ee >>= 1;
  }
  return result;
}

function gf256Inv(a: number): number {
  // Fermat: a^(2^8 - 2) = a^-1 in GF(2^8).
  if ((a & 0xff) === 0) {
    throw new Error("gf256Inv(0)");
  }
  return gf256Pow(a, 254);
}

function shamirSplit(
  secret: Uint8Array,
  threshold: number,
  total: number,
  coeffSeed: Uint8Array,
): Uint8Array[] {
  const coeffsPerByte = threshold - 1;
  const shares: Uint8Array[] = [];
  for (let i = 0; i < total; i++) {
    shares.push(new Uint8Array(secret.length));
  }
  let cursor = 0;
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    const sb = secret[byteIdx] ?? 0;
    const coeffs: number[] = [];
    for (let j = 0; j < coeffsPerByte; j++) {
      coeffs.push(coeffSeed[cursor + j] ?? 0);
    }
    cursor += coeffsPerByte;
    for (let shareIdx = 1; shareIdx <= total; shareIdx++) {
      let y = sb;
      let xPower = 1;
      for (const c of coeffs) {
        xPower = gf256Mul(xPower, shareIdx);
        y ^= gf256Mul(c, xPower);
      }
      const dest = shares[shareIdx - 1];
      if (dest === undefined) {
        throw new Error("internal: share slot missing");
      }
      dest[byteIdx] = y & 0xff;
    }
  }
  return shares;
}

function shamirCombine(idxs: number[], shareBytes: Uint8Array[]): Uint8Array {
  if (idxs.length === 0) {
    return new Uint8Array(0);
  }
  const first = shareBytes[0];
  if (first === undefined) {
    throw new Error("shamirCombine: empty shares");
  }
  const secretLen = first.length;
  const out = new Uint8Array(secretLen);
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let result = 0;
    for (let i = 0; i < idxs.length; i++) {
      const xi = idxs[i] ?? 0;
      const slice = shareBytes[i];
      if (slice === undefined) {
        continue;
      }
      const yi = slice[byteIdx] ?? 0;
      let num = 1;
      let den = 1;
      for (let j = 0; j < idxs.length; j++) {
        if (i === j) {
          continue;
        }
        const xj = idxs[j] ?? 0;
        num = gf256Mul(num, xj);
        den = gf256Mul(den, xi ^ xj);
      }
      const basis = gf256Mul(num, gf256Inv(den));
      result ^= gf256Mul(yi, basis);
    }
    out[byteIdx] = result;
  }
  return out;
}

function handleShamirRoundTrip(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const secret = decodeHex(getString(entry.inputs, "K_bundle_hex"));
  const threshold = getInt(entry.inputs, "threshold");
  const total = getInt(entry.inputs, "total_shares");
  const coeffSeed = decodeHex(getString(entry.inputs, "coefficient_seed_hex"));

  const shares = shamirSplit(secret, threshold, total, coeffSeed);

  // Cross-check pinned shares.
  if (isRecord(entry.intermediates)) {
    const pinnedRaw = entry.intermediates.shares_hex;
    if (Array.isArray(pinnedRaw)) {
      for (let i = 0; i < pinnedRaw.length; i++) {
        const s = pinnedRaw[i];
        if (typeof s !== "string") {
          continue;
        }
        const want = decodeHex(s);
        const got = shares[i];
        if (got === undefined) {
          throw new Error(`shares[${i}] missing`);
        }
        expect(bytesEqual(got, want), `share ${i + 1}`).toBe(true);
      }
    }
  }

  // Threshold combine recovers the secret.
  const subsetRaw = entry.inputs.share_index_subset_for_combine;
  let subset: number[];
  if (Array.isArray(subsetRaw)) {
    subset = subsetRaw.filter((x): x is number => typeof x === "number");
  } else {
    subset = [];
    for (let i = 1; i <= threshold; i++) {
      subset.push(i);
    }
  }
  const subBytes = subset.map((i) => {
    const sh = shares[i - 1];
    if (sh === undefined) {
      throw new Error(`subset references missing share ${i}`);
    }
    return sh;
  });
  const recovered = shamirCombine(subset, subBytes);
  const wantRecover = getBool(entry.expected, "threshold_combine_recovers_K_bundle");
  const gotRecover = bytesEqual(recovered, secret);
  expect(gotRecover).toBe(wantRecover);

  // Sub-threshold MUST NOT recover.
  if (threshold > 1) {
    const smallIdxs: number[] = [];
    const smallBytes: Uint8Array[] = [];
    for (let i = 1; i < threshold; i++) {
      smallIdxs.push(i);
      const sh = shares[i - 1];
      if (sh === undefined) {
        continue;
      }
      smallBytes.push(sh);
    }
    const sub = shamirCombine(smallIdxs, smallBytes);
    const wantSub = getBool(entry.expected, "subthreshold_combine_recovers_K_bundle");
    const gotSub = bytesEqual(sub, secret);
    expect(gotSub).toBe(wantSub);
  }
}

// ---------------------------------------------------------------------------
// first-contact-token (HANDSHAKE.md §2.2a.4)
//
// Two entries:
//   first-contact-token-valid       — PoW + postmark binding both pass
//   first-contact-token-replay-rejected — PoW still passes; postmark
//                                         binding fails => reject
//
// The PoW preimage is `prefix || nonce` (raw bytes, NOT the
// base64:challenge_id:base64(nonce) text form §4 / §2.2b uses).

export function handleFirstContactToken(entry: VectorEntry): void {
  if (!isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: inputs missing`);
  }
  const token = entry.inputs.token_json;
  if (!isRecord(token)) {
    throw new Error(`${entry.id}: token_json not an object`);
  }
  const prefixB64 = getString(token, "prefix");
  const nonceB64 = getString(token, "nonce");
  const prefix = decodeBase64(prefixB64);
  const nonce = decodeBase64(nonceB64);
  const difficulty = getInt(token, "difficulty");
  const postmarkBound = getString(token, "postmark_id");
  const carryingPostmark = getString(entry.inputs, "carrying_envelope_postmark_id");

  const { leadingZeroBits } = firstContactDigest(prefix, nonce);
  const powOK = leadingZeroBits >= difficulty;
  const bindingOK = postmarkBound === carryingPostmark;

  switch (entry.id) {
    case "first-contact-token-valid":
      expect(powOK, "PoW satisfies difficulty").toBe(true);
      expect(bindingOK, "postmark binding").toBe(true);
      break;
    case "first-contact-token-replay-rejected":
      expect(powOK, "PoW still verifies on replay").toBe(true);
      expect(bindingOK, "postmark binding does NOT match for replay").toBe(false);
      break;
    default:
      throw new Error(`first-contact-token: unknown sub-vector ${entry.id}`);
  }
}

// Quiet unused-import lint until later waves reach for these
// across the file.
void confirmationHash;
void computeMAC;
void getOptionalString;
