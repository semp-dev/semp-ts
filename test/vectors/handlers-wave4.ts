/**
 * Wave 4 vectors-runner handlers: verify-only flows that need
 * Ed25519 + the canonical marshaler but no AEAD/KEM.
 *
 * Categories:
 *   - sender-signature  (3 entries: valid, tampered-body, wrong-key)
 *   - delivery-receipt  (3 entries: valid, tampered-envelope, tampered-body)
 *   - forwarding        (3 entries: valid 3-chain, tampered, spoofed)
 *   - migration         (1 entry: 4-signature cooperative chain)
 *   - transparency      (4 entries: STH + inclusion + consistency + augmented)
 *
 * @module
 */

import { expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";

import { canonicalEnvelopeBytes } from "../../src/envelope/index.js";
import { marshal as canonicalMarshal } from "../../src/canonical/index.js";
import { signSignedDoc, verify as ed25519Verify } from "../../src/keys/index.js";
import {
  type VectorEntry,
  bytesEqual,
  decodeBase64,
  decodeHex,
  encodeBase64,
  getBool,
  getField,
  getInt,
  getString,
  isRecord,
} from "./helpers.js";
import { verifySingleSignedDoc } from "./handlers-signed.js";

// ---------------------------------------------------------------------------
// sender-signature

export function handleSenderSignature(entry: VectorEntry): void {
  switch (entry.id) {
    case "sender-signature-valid": {
      if (!isRecord(entry.expected) || !isRecord(entry.inputs)) {
        throw new Error(`${entry.id}: missing inputs/expected`);
      }
      const doc = entry.expected.signed_enclosure_json;
      if (!isRecord(doc)) {
        throw new Error(`${entry.id}: signed_enclosure_json missing`);
      }
      const pub = decodeHex(getString(entry.inputs, "identity_public_key_hex"));
      const { ok } = verifySingleSignedDoc({
        signedJSON: doc,
        signaturePath: "sender_signature.value",
        publicKey: pub,
        prefix: "SEMP-ENCLOSURE-SENDER:",
      });
      expect(ok, "Ed25519 verify").toBe(true);
      // Compose-side: re-sign with the pinned seed and assert the
      // signature matches.
      const preSign = entry.inputs.enclosure_pre_sign_json;
      if (isRecord(preSign)) {
        const composed = signSignedDoc({
          preSignJSON: preSign,
          seed: decodeHex(getString(entry.inputs, "identity_private_seed_hex")),
          signaturePath: "sender_signature.value",
          prefix: "SEMP-ENCLOSURE-SENDER:",
        });
        const pinned = entry.expected.signature_b64;
        if (typeof pinned === "string") {
          expect(composed.signatureB64, "compose").toBe(pinned);
        }
      }
      break;
    }
    case "sender-signature-tampered-body": {
      if (!isRecord(entry.inputs)) {
        throw new Error(`${entry.id}: inputs missing`);
      }
      const doc = entry.inputs.tampered_signed_enclosure_json;
      if (!isRecord(doc)) {
        throw new Error(`${entry.id}: tampered_signed_enclosure_json missing`);
      }
      const pub = decodeHex(getString(entry.inputs, "identity_public_key_hex"));
      const { ok } = verifySingleSignedDoc({
        signedJSON: doc,
        signaturePath: "sender_signature.value",
        publicKey: pub,
        prefix: "SEMP-ENCLOSURE-SENDER:",
      });
      expect(ok, "tampered body MUST NOT verify").toBe(false);
      break;
    }
    case "sender-signature-wrong-key": {
      if (!isRecord(entry.inputs)) {
        throw new Error(`${entry.id}: inputs missing`);
      }
      const doc = entry.inputs.signed_enclosure_json;
      if (!isRecord(doc)) {
        throw new Error(`${entry.id}: signed_enclosure_json missing`);
      }
      // Verify with claimed (wrong) key — must fail.
      const claimed = decodeHex(getString(entry.inputs, "claimed_identity_public_key_hex"));
      const claimedRes = verifySingleSignedDoc({
        signedJSON: doc,
        signaturePath: "sender_signature.value",
        publicKey: claimed,
        prefix: "SEMP-ENCLOSURE-SENDER:",
      });
      expect(claimedRes.ok, "claimed key MUST NOT verify").toBe(false);
      // Sanity check: actual signer key DOES verify.
      const actual = decodeHex(getString(entry.inputs, "actual_signer_public_key_hex"));
      const actualRes = verifySingleSignedDoc({
        signedJSON: doc,
        signaturePath: "sender_signature.value",
        publicKey: actual,
        prefix: "SEMP-ENCLOSURE-SENDER:",
      });
      expect(actualRes.ok, "actual signer key sanity").toBe(true);
      break;
    }
    default:
      throw new Error(`sender-signature: unknown sub-vector ${entry.id}`);
  }
}

// ---------------------------------------------------------------------------
// delivery-receipt

export function handleDeliveryReceipt(entry: VectorEntry): void {
  switch (entry.id) {
    case "delivery-receipt-valid":
      handleDeliveryReceiptValid(entry);
      break;
    case "delivery-receipt-tampered-envelope":
      handleDeliveryReceiptTamperedEnvelope(entry);
      break;
    case "delivery-receipt-tampered-body":
      handleDeliveryReceiptTamperedBody(entry);
      break;
    default:
      throw new Error(`delivery-receipt: unknown sub-vector ${entry.id}`);
  }
}

function handleDeliveryReceiptValid(entry: VectorEntry): void {
  if (!isRecord(entry.expected) || !isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: missing`);
  }
  const doc = entry.expected.signed_receipt_json;
  if (!isRecord(doc)) {
    throw new Error(`${entry.id}: signed_receipt_json missing`);
  }
  const pub = decodeHex(getString(entry.inputs, "recipient_domain_pub_hex"));
  const { ok } = verifySingleSignedDoc({
    signedJSON: doc,
    signaturePath: "signature.value",
    publicKey: pub,
    prefix: "SEMP-DELIVERY-RECEIPT:",
  });
  expect(ok, "receipt signature").toBe(true);

  // envelope_hash recomputation: SHA-256(canonical(reference_envelope))
  // MUST equal receipt.envelope_hash.value.
  const envJSON = entry.inputs.reference_envelope_json;
  if (envJSON !== undefined) {
    const canonicalEnv = canonicalEnvelopeBytes(envJSON);
    const sum = sha256(canonicalEnv);
    const wantHash = encodeBase64(sum);
    const envHashObj = doc.envelope_hash;
    if (!isRecord(envHashObj)) {
      throw new Error("signed receipt missing envelope_hash");
    }
    expect(envHashObj.value, "envelope_hash.value").toBe(wantHash);
  }

  // Compose-side: re-sign with the pinned seed.
  const preSign = entry.inputs.receipt_pre_sign_json;
  if (isRecord(preSign)) {
    const composed = signSignedDoc({
      preSignJSON: preSign,
      seed: decodeHex(getString(entry.inputs, "recipient_domain_seed_hex")),
      signaturePath: "signature.value",
      prefix: "SEMP-DELIVERY-RECEIPT:",
    });
    const pinned = entry.expected.signature_b64;
    if (typeof pinned === "string") {
      expect(composed.signatureB64, "compose receipt signature").toBe(pinned);
    }
  }
}

function handleDeliveryReceiptTamperedEnvelope(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const doc = entry.inputs.signed_receipt_json;
  if (!isRecord(doc)) {
    throw new Error(`${entry.id}: signed_receipt_json missing`);
  }
  const pub = decodeHex(getString(entry.inputs, "recipient_domain_pub_hex"));
  const { ok } = verifySingleSignedDoc({
    signedJSON: doc,
    signaturePath: "signature.value",
    publicKey: pub,
    prefix: "SEMP-DELIVERY-RECEIPT:",
  });
  const wantSigOK = getBool(entry.expected, "receipt_signature_still_verifies");
  expect(ok).toBe(wantSigOK);

  // Recompute the tampered envelope's hash and compare.
  const envJSON = entry.inputs.tampered_envelope_json;
  if (envJSON === undefined) {
    return;
  }
  const canonicalEnv = canonicalEnvelopeBytes(envJSON);
  const sum = sha256(canonicalEnv);
  const recomputedHash = encodeBase64(sum);
  const envHashObj = doc.envelope_hash;
  const receiptHash = isRecord(envHashObj) && typeof envHashObj.value === "string"
    ? envHashObj.value
    : "";
  const matches = recomputedHash === receiptHash;
  const wantMatches = getBool(entry.expected, "envelope_hash_matches_recomputation");
  expect(matches, "envelope_hash_matches_recomputation").toBe(wantMatches);
}

function handleDeliveryReceiptTamperedBody(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const doc = entry.inputs.tampered_receipt_json;
  if (!isRecord(doc)) {
    throw new Error(`${entry.id}: tampered_receipt_json missing`);
  }
  const pub = decodeHex(getString(entry.inputs, "recipient_domain_pub_hex"));
  const { ok } = verifySingleSignedDoc({
    signedJSON: doc,
    signaturePath: "signature.value",
    publicKey: pub,
    prefix: "SEMP-DELIVERY-RECEIPT:",
  });
  const wantSigOK = getBool(entry.expected, "signature_verifies");
  expect(ok).toBe(wantSigOK);
}

// ---------------------------------------------------------------------------
// forwarding (3-step chain per ENVELOPE.md §6.6.4)

export function handleForwarding(entry: VectorEntry): void {
  switch (entry.id) {
    case "forward-valid-three-step-chain":
      runForwardingChain(
        entry,
        getOuterFromExpected(entry, "outer_enclosure_json"),
        true,
        true,
        true,
      );
      break;
    case "forward-tampered-original-content":
      if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
        throw new Error(`${entry.id}: missing`);
      }
      runForwardingChain(
        entry,
        entry.inputs.tampered_outer_enclosure_json,
        getBool(entry.expected, "step_1_outer_sender_signature_verifies"),
        getBool(entry.expected, "step_2_forwarder_attestation_verifies"),
        getBool(entry.expected, "step_3_original_sender_signature_verifies"),
      );
      break;
    case "forward-spoofed-outer-signer": {
      if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
        throw new Error(`${entry.id}: missing`);
      }
      const outer = entry.inputs.spoofed_outer_enclosure_json;
      if (!isRecord(outer)) {
        throw new Error(`${entry.id}: spoofed_outer_enclosure_json missing`);
      }
      const claimed = decodeHex(getString(entry.inputs, "claimed_forwarder_pub_hex"));
      const claimedRes = verifySingleSignedDoc({
        signedJSON: outer,
        signaturePath: "sender_signature.value",
        publicKey: claimed,
        prefix: "SEMP-ENCLOSURE-SENDER:",
      });
      const wantClaimed = getBool(
        entry.expected,
        "step_1_outer_sender_signature_verifies_against_claimed_key",
      );
      expect(claimedRes.ok, "spoofed claimed key").toBe(wantClaimed);
      // Sanity: actual signer's pubkey DOES verify.
      const actualHex = entry.inputs.actual_outer_signer_pub_hex;
      if (typeof actualHex === "string") {
        const actual = decodeHex(actualHex);
        const sanity = verifySingleSignedDoc({
          signedJSON: outer,
          signaturePath: "sender_signature.value",
          publicKey: actual,
          prefix: "SEMP-ENCLOSURE-SENDER:",
        });
        expect(sanity.ok, "actual signer sanity").toBe(true);
      }
      break;
    }
    default:
      throw new Error(`forwarding: unknown sub-vector ${entry.id}`);
  }
}

function getOuterFromExpected(entry: VectorEntry, field: string): unknown {
  if (!isRecord(entry.expected)) {
    throw new Error(`${entry.id}: expected missing`);
  }
  return entry.expected[field];
}

function runForwardingChain(
  entry: VectorEntry,
  outerRaw: unknown,
  want1: boolean,
  want2: boolean,
  want3: boolean,
): void {
  if (!isRecord(outerRaw)) {
    throw new Error(`${entry.id}: outer enclosure not an object`);
  }
  if (!isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: inputs missing`);
  }
  const forwarderPub = decodeHex(
    typeof entry.inputs.forwarder_identity_pub_hex === "string"
      ? entry.inputs.forwarder_identity_pub_hex
      : getString(entry.inputs, "forwarder_pub_hex"),
  );
  const originalPub = decodeHex(
    typeof entry.inputs.original_sender_identity_pub_hex === "string"
      ? entry.inputs.original_sender_identity_pub_hex
      : getString(entry.inputs, "original_sender_pub_hex"),
  );

  // Step 1: outer document, sender_signature.value blanked, forwarder pub.
  const step1 = verifySingleSignedDoc({
    signedJSON: outerRaw,
    signaturePath: "sender_signature.value",
    publicKey: forwarderPub,
    prefix: "SEMP-ENCLOSURE-SENDER:",
  });
  expect(step1.ok, "step 1 (outer sender_signature)").toBe(want1);

  // Step 2: forwarded_from subtree, forwarder_attestation.value blanked.
  const from = outerRaw.forwarded_from;
  if (!isRecord(from)) {
    throw new Error(`${entry.id}: forwarded_from missing`);
  }
  const step2 = verifySingleSignedDoc({
    signedJSON: from,
    signaturePath: "forwarder_attestation.value",
    publicKey: forwarderPub,
    prefix: "SEMP-FORWARDER-ATTESTATION:",
  });
  expect(step2.ok, "step 2 (forwarder_attestation)").toBe(want2);

  // Step 3: original_enclosure_plaintext subtree.
  const orig = from.original_enclosure_plaintext;
  if (!isRecord(orig)) {
    throw new Error(`${entry.id}: original_enclosure_plaintext missing`);
  }
  const step3 = verifySingleSignedDoc({
    signedJSON: orig,
    signaturePath: "sender_signature.value",
    publicKey: originalPub,
    prefix: "SEMP-ENCLOSURE-SENDER:",
  });
  expect(step3.ok, "step 3 (original sender_signature)").toBe(want3);
}

// ---------------------------------------------------------------------------
// migration: 4-signature chain (cooperative)
//
// Each signer signs over a document where every PRIOR signer's
// value is populated and every LATER signer's value is blank. The
// runner replays the blanking sequence against the final record,
// cross-checks the per-step canonical bytes against
// intermediates.signature_chain, and Ed25519-verifies each step.

export function handleMigration(entry: VectorEntry): void {
  if (entry.id !== "migration-cooperative-four-signature-chain") {
    throw new Error(`migration: unknown sub-vector ${entry.id}`);
  }
  if (!isRecord(entry.expected) || !isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: missing`);
  }
  const signedDoc = entry.expected.signed_record_json;
  if (!isRecord(signedDoc)) {
    throw new Error(`${entry.id}: signed_record_json missing`);
  }

  const chain: Array<{
    fieldName: string;
    pubHexKey: string;
    role: string;
  }> = [
    { fieldName: "old_identity_signature", pubHexKey: "old_identity_pub_hex", role: "old_identity" },
    { fieldName: "new_identity_signature", pubHexKey: "new_identity_pub_hex", role: "new_identity" },
    { fieldName: "new_domain_signature", pubHexKey: "new_domain_pub_hex", role: "new_domain" },
    { fieldName: "old_domain_signature", pubHexKey: "old_domain_pub_hex", role: "old_domain" },
  ];

  const interChain = (() => {
    if (!isRecord(entry.intermediates)) {
      return undefined;
    }
    const c = entry.intermediates.signature_chain;
    return Array.isArray(c) ? c : undefined;
  })();

  let allOK = true;
  for (let i = 0; i < chain.length; i++) {
    const step = chain[i];
    if (step === undefined) {
      continue;
    }
    // Build the per-step view: blank step[i] AND every step[j>i],
    // leave step[j<i] populated.
    const stepDoc = JSON.parse(JSON.stringify(signedDoc)) as Record<string, unknown>;
    for (let j = i; j < chain.length; j++) {
      const other = chain[j];
      if (other === undefined) {
        continue;
      }
      const obj = stepDoc[other.fieldName];
      if (!isRecord(obj)) {
        throw new Error(`step ${i + 1}: missing ${other.fieldName}`);
      }
      obj.value = "";
    }
    const blanked = canonicalMarshal(stepDoc);

    // Cross-check pinned canonical for this step.
    if (interChain !== undefined && i < interChain.length) {
      const stepEntry = interChain[i];
      if (isRecord(stepEntry)) {
        const want = stepEntry.canonical_with_blanked_signature_utf8;
        if (typeof want === "string") {
          expect(new TextDecoder().decode(blanked), `step ${i + 1} canonical`).toBe(want);
        }
      }
    }

    // Pull this signer's signature from the FINAL doc.
    const sigObj = signedDoc[step.fieldName];
    if (!isRecord(sigObj) || typeof sigObj.value !== "string") {
      throw new Error(`step ${i + 1} (${step.role}): signature missing`);
    }
    const sigBytes = decodeBase64(sigObj.value);
    const pub = decodeHex(getString(entry.inputs, step.pubHexKey));
    const signingInput = concat(new TextEncoder().encode("SEMP-MIGRATION-RECORD:"), blanked);
    const ok = ed25519Verify(pub, sigBytes, signingInput);
    if (!ok) {
      allOK = false;
    }
    expect(ok, `step ${i + 1} (${step.role})`).toBe(true);
  }
  const wantAll = getBool(entry.expected, "all_four_signatures_verify");
  expect(allOK).toBe(wantAll);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ---------------------------------------------------------------------------
// transparency (RFC 6962 Merkle math + STH signature)

export function handleTransparency(entry: VectorEntry): void {
  switch (entry.id) {
    case "transparency-sth-signed":
      handleSTHSigned(entry);
      break;
    case "transparency-inclusion-proof":
      handleInclusionProof(entry);
      break;
    case "transparency-consistency-proof":
      handleConsistencyProof(entry);
      break;
    case "transparency-augmented-key-fetch":
      handleAugmentedKeyFetch(entry);
      break;
    default:
      throw new Error(`transparency: unknown sub-vector ${entry.id}`);
  }
}

function handleSTHSigned(entry: VectorEntry): void {
  if (!isRecord(entry.expected) || !isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: missing`);
  }
  const doc = entry.expected.sth_signed_json;
  if (!isRecord(doc)) {
    throw new Error(`${entry.id}: sth_signed_json missing`);
  }
  const pub = decodeHex(getString(entry.inputs, "domain_pub_hex"));
  const { ok } = verifySingleSignedDoc({
    signedJSON: doc,
    signaturePath: "signature.value",
    publicKey: pub,
    prefix: "SEMP-TRANSPARENCY-STH:",
  });
  expect(ok).toBe(true);

  // Compose-side cross-check.
  const preSign = entry.inputs.sth_pre_sign_json;
  if (isRecord(preSign)) {
    const composed = signSignedDoc({
      preSignJSON: preSign,
      seed: decodeHex(getString(entry.inputs, "domain_seed_hex")),
      signaturePath: "signature.value",
      prefix: "SEMP-TRANSPARENCY-STH:",
    });
    const pinned = entry.expected.signature_b64;
    if (typeof pinned === "string") {
      expect(composed.signatureB64, "compose STH signature").toBe(pinned);
    }
  }
}

function handleInclusionProof(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const leafIndex = getInt(entry.inputs, "leaf_index");
  const logSize = getInt(entry.inputs, "log_size");
  const leafHash = decodeHex(getString(entry.inputs, "leaf_hash_hex"));
  const expectedRoot = decodeHex(getString(entry.inputs, "expected_root_hex"));
  const path = decodeMerklePath(getField(entry.inputs, "path_hex"));

  const valid = verifyInclusionProofRFC6962(leafHash, leafIndex, logSize, path, expectedRoot);
  expect(valid).toBe(getBool(entry.expected, "valid_path_verifies"));

  const tamperedHex = entry.expected.tampered_path_first_element_hex;
  if (typeof tamperedHex === "string") {
    const tamperedFirst = decodeHex(tamperedHex);
    const tamperedPath = path.slice();
    tamperedPath[0] = tamperedFirst;
    const tamperedValid = verifyInclusionProofRFC6962(
      leafHash,
      leafIndex,
      logSize,
      tamperedPath,
      expectedRoot,
    );
    expect(tamperedValid).toBe(getBool(entry.expected, "tampered_path_verifies"));
  }
}

function handleConsistencyProof(entry: VectorEntry): void {
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing`);
  }
  const n1 = getInt(entry.inputs, "n1");
  const n2 = getInt(entry.inputs, "n2");
  const oldRoot = decodeHex(getString(entry.inputs, "root_n1_hex"));
  const newRoot = decodeHex(getString(entry.inputs, "root_n2_hex"));
  const path = decodeMerklePath(getField(entry.inputs, "path_hex"));

  const valid = verifyConsistencyProofRFC6962(n1, n2, oldRoot, newRoot, path);
  expect(valid).toBe(getBool(entry.expected, "valid_path_verifies"));
}

function handleAugmentedKeyFetch(entry: VectorEntry): void {
  if (!isRecord(entry.expected) || !isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: missing`);
  }
  const resp = entry.expected.augmented_response_json;
  if (!isRecord(resp)) {
    throw new Error(`${entry.id}: augmented_response_json missing`);
  }
  const keys = resp.keys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error(`${entry.id}: augmented response missing keys[]`);
  }
  const first = keys[0];
  if (!isRecord(first)) {
    throw new Error(`${entry.id}: keys[0] not an object`);
  }
  const trans = first.transparency;
  if (!isRecord(trans)) {
    throw new Error(`${entry.id}: keys[0].transparency missing`);
  }
  const sth = trans.sth;
  if (!isRecord(sth)) {
    throw new Error(`${entry.id}: keys[0].transparency.sth missing`);
  }
  const pub = decodeHex(getString(entry.inputs, "domain_pub_hex"));
  const { ok } = verifySingleSignedDoc({
    signedJSON: sth,
    signaturePath: "signature.value",
    publicKey: pub,
    prefix: "SEMP-TRANSPARENCY-STH:",
  });
  expect(ok).toBe(getBool(entry.expected, "sth_signature_verifies"));
}

// decodeMerklePath unpacks a Merkle proof path. The vectors encode
// path_hex as either an array of hex strings (one per node) or a
// single concatenated hex blob; this handles both.
function decodeMerklePath(raw: unknown): Uint8Array[] {
  if (raw === undefined || raw === null) {
    return [];
  }
  if (Array.isArray(raw)) {
    return raw
      .filter((s): s is string => typeof s === "string")
      .map((s) => decodeHex(s));
  }
  if (typeof raw === "string") {
    if (raw.length === 0) {
      return [];
    }
    const all = decodeHex(raw);
    if (all.length % 32 !== 0) {
      throw new Error(`merkle path bytes ${all.length} not a multiple of 32`);
    }
    const out: Uint8Array[] = [];
    for (let i = 0; i < all.length; i += 32) {
      out.push(all.slice(i, i + 32));
    }
    return out;
  }
  throw new Error("merkle path: unknown encoding");
}

// RFC 6962 §2.1.1 inclusion proof verification.
function verifyInclusionProofRFC6962(
  leafHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  path: Uint8Array[],
  expectedRoot: Uint8Array,
): boolean {
  if (leafIndex < 0 || leafIndex >= treeSize) {
    return false;
  }
  let hash = leafHash.slice();
  let fn = leafIndex;
  let sn = treeSize - 1;
  for (const p of path) {
    if (sn === 0) {
      return false;
    }
    if (fn % 2 === 1 || fn === sn) {
      hash = innerHash(p, hash);
      while (fn % 2 === 0) {
        fn = fn >>> 1;
        sn = sn >>> 1;
      }
    } else {
      hash = innerHash(hash, p);
    }
    fn = fn >>> 1;
    sn = sn >>> 1;
  }
  return sn === 0 && bytesEqual(hash, expectedRoot);
}

// RFC 6962 §2.1.2 consistency proof verification.
function verifyConsistencyProofRFC6962(
  n1: number,
  n2: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  path: Uint8Array[],
): boolean {
  if (n1 === n2) {
    return path.length === 0 && bytesEqual(oldRoot, newRoot);
  }
  if (n1 === 0 || n1 > n2) {
    return false;
  }
  let node = n1 - 1;
  let lastNode = n2 - 1;
  while (node % 2 === 1) {
    node = node >>> 1;
    lastNode = lastNode >>> 1;
  }
  let oldHash: Uint8Array;
  let newHash: Uint8Array;
  let p = path;
  if (p.length === 0) {
    return false;
  }
  if (node > 0) {
    const first = p[0];
    if (first === undefined) {
      return false;
    }
    oldHash = first;
    newHash = first;
    p = p.slice(1);
  } else {
    oldHash = oldRoot;
    newHash = oldRoot;
  }
  for (const step of p) {
    if (lastNode === 0) {
      return false;
    }
    if (node % 2 === 1 || node === lastNode) {
      oldHash = innerHash(step, oldHash);
      newHash = innerHash(step, newHash);
      while (node % 2 === 0) {
        node = node >>> 1;
        lastNode = lastNode >>> 1;
      }
    } else {
      newHash = innerHash(newHash, step);
    }
    node = node >>> 1;
    lastNode = lastNode >>> 1;
  }
  return lastNode === 0 && bytesEqual(oldHash, oldRoot) && bytesEqual(newHash, newRoot);
}

function innerHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = 0x01;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}
