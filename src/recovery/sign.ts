/**
 * Sign / verify primitives for recovery wire records per
 * RECOVERY.md §5.2, §5.3, §7.3, §7.5.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";
import { sign as ed25519Sign, verify as ed25519Verify } from "../keys/index.js";
import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

import {
  type RecoverySetManifest,
  type RecoveryShareRecord,
  type SuccessorRecord,
  RecoveryManifestPrefix,
  RecoveryShareSignaturePrefix,
  SignatureAlgorithmEd25519,
  SuccessorRecordPrefix,
} from "./types.js";

// ---------------------------------------------------------------------------
// SuccessorRecord - three-signature record per §7.3

/**
 * Pre-populate the algorithm + key_id fields on all three signature
 * blocks so the canonical bytes are stable across the three signing
 * passes. Every signing pass signs the SAME canonical bytes (with
 * all three `value` fields elided), so this MUST be called before
 * any of the {@link signSuccessor*} functions.
 */
export function prepareSuccessorSignatures(
  r: SuccessorRecord,
  recoveryKeyId: string,
  newKeyId: string,
  domainKeyId: string,
): void {
  r.recovery_signature.algorithm = SignatureAlgorithmEd25519;
  r.recovery_signature.key_id = recoveryKeyId;
  r.recovery_signature.value = "";
  r.new_key_signature.algorithm = SignatureAlgorithmEd25519;
  r.new_key_signature.key_id = newKeyId;
  r.new_key_signature.value = "";
  r.domain_signature.algorithm = SignatureAlgorithmEd25519;
  r.domain_signature.key_id = domainKeyId;
  r.domain_signature.value = "";
}

/** Sign `r.recovery_signature` per §7.3. */
export function signSuccessorRecovery(
  r: SuccessorRecord,
  recoveryPriv: Uint8Array,
  recoveryKeyId: string,
): string {
  return signOneOfThree(
    r,
    "recovery_signature",
    recoveryPriv,
    recoveryKeyId,
    "recoveryKeyId",
  );
}

/** Sign `r.new_key_signature` per §7.3. */
export function signSuccessorNewKey(
  r: SuccessorRecord,
  newIdentityPriv: Uint8Array,
  newKeyId: string,
): string {
  return signOneOfThree(
    r,
    "new_key_signature",
    newIdentityPriv,
    newKeyId,
    "newKeyId",
  );
}

/** Sign `r.domain_signature` per §7.3. */
export function signSuccessorDomain(
  r: SuccessorRecord,
  domainPriv: Uint8Array,
  domainKeyId: string,
): string {
  return signOneOfThree(
    r,
    "domain_signature",
    domainPriv,
    domainKeyId,
    "domainKeyId",
  );
}

function signOneOfThree(
  r: SuccessorRecord,
  field: "recovery_signature" | "new_key_signature" | "domain_signature",
  priv: Uint8Array,
  keyId: string,
  argLabel: string,
): string {
  if (priv.length === 0) {
    throw new Error(`recovery: empty private key for ${field}`);
  }
  if (keyId === "") {
    throw new Error(`recovery: empty ${argLabel}`);
  }
  validateSuccessorRecord(r, { skipSignatureCheck: true });
  const sigBlock = r[field];
  if (sigBlock.algorithm === "" || sigBlock.key_id === "") {
    throw new Error(
      `recovery: call prepareSuccessorSignatures before sign${field}`,
    );
  }
  if (sigBlock.key_id !== keyId) {
    throw new Error(
      `recovery: ${field}.key_id ${JSON.stringify(sigBlock.key_id)} does not match passed ${argLabel} ${JSON.stringify(keyId)}`,
    );
  }
  sigBlock.value = "";
  const canonical = canonicalSuccessorBytesElidingThreeSignatures(r);
  const signingInput = concat(
    new TextEncoder().encode(SuccessorRecordPrefix),
    canonical,
  );
  const sig = ed25519Sign(priv, signingInput);
  const sigB64 = base64Encode(sig);
  sigBlock.value = sigB64;
  return sigB64;
}

/**
 * Verify the two device-side signatures (recovery, new_key) on `r`
 * and accept an empty `domain_signature.value`. This is what the
 * home server runs on receipt of a key-compromise rotation cascade
 * (KEY.md §10.5.5): the device produced both signatures, the server
 * has not yet added its own.
 */
export function verifySuccessorTwoSignatures(
  r: SuccessorRecord,
  recoveryVerifyPub: Uint8Array,
  newKeyPub: Uint8Array,
): boolean {
  // Skip the full-signature-presence check; this two-signature
  // entry point intentionally accepts an empty domain signature.
  validateSuccessorRecord(r, { skipSignatureCheck: true });
  if (r.recovery_signature.value === "" || r.new_key_signature.value === "") {
    return false;
  }
  if (r.domain_signature.value !== "") {
    throw new Error(
      "recovery: verifySuccessorTwoSignatures called on a fully-signed record; use verifySuccessorRecord",
    );
  }
  const canonical = canonicalSuccessorBytesElidingThreeSignatures(r);
  const signingInput = concat(
    new TextEncoder().encode(SuccessorRecordPrefix),
    canonical,
  );
  if (
    !ed25519Verify(
      recoveryVerifyPub,
      base64Decode(r.recovery_signature.value),
      signingInput,
    )
  ) {
    return false;
  }
  if (
    !ed25519Verify(
      newKeyPub,
      base64Decode(r.new_key_signature.value),
      signingInput,
    )
  ) {
    return false;
  }
  return true;
}

/** Verify all three signatures on `r` per §7.5. */
export function verifySuccessorRecord(
  r: SuccessorRecord,
  recoveryVerifyPub: Uint8Array,
  newKeyPub: Uint8Array,
  domainPub: Uint8Array,
): boolean {
  validateSuccessorRecord(r);
  if (
    r.recovery_signature.value === "" ||
    r.new_key_signature.value === "" ||
    r.domain_signature.value === ""
  ) {
    return false;
  }
  const canonical = canonicalSuccessorBytesElidingThreeSignatures(r);
  const signingInput = concat(
    new TextEncoder().encode(SuccessorRecordPrefix),
    canonical,
  );
  return (
    ed25519Verify(
      recoveryVerifyPub,
      base64Decode(r.recovery_signature.value),
      signingInput,
    ) &&
    ed25519Verify(
      newKeyPub,
      base64Decode(r.new_key_signature.value),
      signingInput,
    ) &&
    ed25519Verify(
      domainPub,
      base64Decode(r.domain_signature.value),
      signingInput,
    )
  );
}

/** Structural validation per §7. Throws on first violation. */
export function validateSuccessorRecord(
  r: SuccessorRecord,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (r.type !== "SEMP_SUCCESSOR") {
    throw new Error(`recovery: successor type ${JSON.stringify(r.type)}, want SEMP_SUCCESSOR`);
  }
  for (const f of ["user_id", "prior_key_id", "new_key_id", "new_public_key", "recovered_at"] as const) {
    if (typeof r[f] !== "string" || r[f] === "") {
      throw new Error(`recovery: successor record missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(r.recovered_at))) {
    throw new Error("recovery: recovered_at is not ISO 8601");
  }
  for (const f of ["recovery_signature", "new_key_signature", "domain_signature"] as const) {
    if (typeof r[f]?.algorithm !== "string") {
      throw new Error(`recovery: ${f}.algorithm missing`);
    }
    if (typeof r[f]?.key_id !== "string") {
      throw new Error(`recovery: ${f}.key_id missing`);
    }
    if (typeof r[f]?.value !== "string") {
      throw new Error(`recovery: ${f}.value must be a string`);
    }
  }
  if (
    !opts.skipSignatureCheck &&
    (r.recovery_signature.value === "" ||
      r.new_key_signature.value === "" ||
      r.domain_signature.value === "")
  ) {
    throw new Error("recovery: successor record missing one or more signatures");
  }
}

/**
 * Canonical bytes of `r` with all three signature `value` fields
 * elided to "" (algorithm and key_id are covered).
 */
function canonicalSuccessorBytesElidingThreeSignatures(
  r: SuccessorRecord,
): Uint8Array {
  const clone: Record<string, unknown> = JSON.parse(JSON.stringify(r));
  for (const f of ["recovery_signature", "new_key_signature", "domain_signature"] as const) {
    const sig = clone[f] as Record<string, unknown>;
    sig.value = "";
  }
  return canonicalMarshal(clone);
}

// ---------------------------------------------------------------------------
// RecoverySetManifest - single user-identity signature per §5.2

/**
 * Sign `m.signature` with the user's identity private key per §5.2.
 * Pre-populates algorithm + key_id so the canonical bytes cover them.
 */
export function signManifest(
  m: RecoverySetManifest,
  identityPriv: Uint8Array,
  identityKeyId: string,
): string {
  if (identityKeyId === "") {
    throw new Error("recovery: empty identity key_id");
  }
  validateManifest(m, { skipSignatureCheck: true });
  m.signature.algorithm = SignatureAlgorithmEd25519;
  m.signature.key_id = identityKeyId;
  m.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: m as unknown as Record<string, unknown>,
    seed: identityPriv,
    signaturePath: "signature.value",
    prefix: RecoveryManifestPrefix,
  });
  // signSignedDoc returns a clone; mutate the caller-supplied object
  // in place so behavior matches the other recovery sign* functions.
  m.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify `m.signature` against `identityPub` per §5.2. */
export function verifyManifest(
  m: RecoverySetManifest,
  identityPub: Uint8Array,
): boolean {
  validateManifest(m);
  if (m.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: m as unknown as Record<string, unknown>,
    publicKey: identityPub,
    signaturePath: "signature.value",
    prefix: RecoveryManifestPrefix,
  });
  return ok;
}

/** Structural validation per §5.2. Throws on first violation. */
export function validateManifest(
  m: RecoverySetManifest,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (m.type !== "SEMP_RECOVERY_SET_MANIFEST") {
    throw new Error(
      `recovery: manifest type ${JSON.stringify(m.type)}, want SEMP_RECOVERY_SET_MANIFEST`,
    );
  }
  if (typeof m.bundle_id !== "string" || m.bundle_id === "") {
    throw new Error("recovery: manifest missing bundle_id");
  }
  if (!Number.isInteger(m.threshold) || m.threshold < 1) {
    throw new Error(`recovery: manifest threshold ${m.threshold} MUST be >= 1`);
  }
  if (!Number.isInteger(m.total_shares) || m.total_shares < m.threshold) {
    throw new Error(
      `recovery: manifest total_shares ${m.total_shares} MUST be >= threshold ${m.threshold}`,
    );
  }
  if (!Array.isArray(m.contributors) || m.contributors.length !== m.total_shares) {
    throw new Error(
      `recovery: manifest contributors length ${m.contributors?.length ?? 0} MUST equal total_shares ${m.total_shares}`,
    );
  }
  if (typeof m.issued_at !== "string" || m.issued_at === "") {
    throw new Error("recovery: manifest missing issued_at");
  }
  const seenIndex = new Set<number>();
  const seenDevice = new Set<string>();
  for (let i = 0; i < m.contributors.length; i++) {
    const c = m.contributors[i]!;
    if (
      !Number.isInteger(c.share_index) ||
      c.share_index < 1 ||
      c.share_index > m.total_shares
    ) {
      throw new Error(
        `recovery: manifest contributors[${i}] share_index ${c.share_index} out of [1, ${m.total_shares}]`,
      );
    }
    if (seenIndex.has(c.share_index)) {
      throw new Error(
        `recovery: manifest share_index ${c.share_index} appears more than once`,
      );
    }
    seenIndex.add(c.share_index);
    if (typeof c.device_id !== "string" || c.device_id === "") {
      throw new Error(`recovery: manifest contributors[${i}] missing device_id`);
    }
    if (seenDevice.has(c.device_id)) {
      throw new Error(
        `recovery: manifest device_id ${JSON.stringify(c.device_id)} appears more than once`,
      );
    }
    seenDevice.add(c.device_id);
    if (
      typeof c.device_identity_pubkey?.public_key !== "string" ||
      c.device_identity_pubkey.public_key === ""
    ) {
      throw new Error(
        `recovery: manifest contributors[${i}] missing device_identity_pubkey.public_key`,
      );
    }
    if (
      typeof c.device_identity_pubkey?.algorithm !== "string" ||
      c.device_identity_pubkey.algorithm === ""
    ) {
      throw new Error(
        `recovery: manifest contributors[${i}] missing device_identity_pubkey.algorithm`,
      );
    }
  }
  if (!opts.skipSignatureCheck && m.signature.value === "") {
    throw new Error("recovery: manifest is unsigned");
  }
}

// ---------------------------------------------------------------------------
// RecoveryShareRecord - single device-identity signature per §5.3

/** Sign `s.device_signature` with the device's identity private key per §5.3. */
export function signShareRecord(
  s: RecoveryShareRecord,
  devicePriv: Uint8Array,
  deviceKeyId: string,
): string {
  if (deviceKeyId === "") {
    throw new Error("recovery: empty device key_id");
  }
  validateShareRecord(s, { skipSignatureCheck: true });
  s.device_signature.algorithm = SignatureAlgorithmEd25519;
  s.device_signature.key_id = deviceKeyId;
  s.device_signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: s as unknown as Record<string, unknown>,
    seed: devicePriv,
    signaturePath: "device_signature.value",
    prefix: RecoveryShareSignaturePrefix,
  });
  s.device_signature.value = (signedJSON.device_signature as { value: string }).value;
  return signatureB64;
}

/** Verify `s.device_signature` against `devicePub` per §5.3. */
export function verifyShareRecord(
  s: RecoveryShareRecord,
  devicePub: Uint8Array,
): boolean {
  validateShareRecord(s);
  if (s.device_signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: s as unknown as Record<string, unknown>,
    publicKey: devicePub,
    signaturePath: "device_signature.value",
    prefix: RecoveryShareSignaturePrefix,
  });
  return ok;
}

/** Structural validation per §5.3. Throws on first violation. */
export function validateShareRecord(
  s: RecoveryShareRecord,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (s.type !== "SEMP_RECOVERY_SHARE") {
    throw new Error(
      `recovery: share type ${JSON.stringify(s.type)}, want SEMP_RECOVERY_SHARE`,
    );
  }
  if (typeof s.bundle_id !== "string" || s.bundle_id === "") {
    throw new Error("recovery: share record missing bundle_id");
  }
  if (!Number.isInteger(s.share_index) || s.share_index < 1) {
    throw new Error(
      `recovery: share record share_index ${s.share_index} MUST be >= 1`,
    );
  }
  if (
    !Number.isInteger(s.threshold) ||
    s.threshold < 1 ||
    !Number.isInteger(s.total_shares) ||
    s.total_shares < s.threshold ||
    s.share_index > s.total_shares
  ) {
    throw new Error(
      `recovery: share record (threshold=${s.threshold}, total_shares=${s.total_shares}, share_index=${s.share_index}) is inconsistent`,
    );
  }
  if (typeof s.device_id !== "string" || s.device_id === "") {
    throw new Error("recovery: share record missing device_id");
  }
  if (typeof s.share_value !== "string" || s.share_value === "") {
    throw new Error("recovery: share record missing share_value");
  }
  if (typeof s.issued_at !== "string" || s.issued_at === "") {
    throw new Error("recovery: share record missing issued_at");
  }
  if (!opts.skipSignatureCheck && s.device_signature.value === "") {
    throw new Error("recovery: share record is unsigned");
  }
}

/**
 * Cross-check that `s` belongs to `m` per §5.3 step 2: bundle_id,
 * share_index, device_id, threshold, total_shares MUST all match.
 * Returns true when every check passes.
 */
export function checkShareMatchesManifest(
  s: RecoveryShareRecord,
  m: RecoverySetManifest,
): boolean {
  if (s.bundle_id !== m.bundle_id) {
    return false;
  }
  if (s.threshold !== m.threshold) {
    return false;
  }
  if (s.total_shares !== m.total_shares) {
    return false;
  }
  for (const c of m.contributors) {
    if (c.share_index !== s.share_index) {
      continue;
    }
    return c.device_id === s.device_id;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helpers

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
