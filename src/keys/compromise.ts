/**
 * KEY.md §10.5.5 atomic identity-key rotation cascade.
 *
 * Revoking a device with reason `key_compromise` MUST be done in
 * the same transaction as rotating to a new identity key plus a new
 * encryption key - the compromised device held the shared identity
 * private key, so the adversary holds it too. A partial cascade
 * (device revoked but identity key not rotated) leaves the account
 * vulnerable and is a specification violation.
 *
 * The bundle a revoking device produces:
 *
 *   1. {@link DeviceRevocation} for the compromised device, reason
 *      `key_compromise`, signed by the prior identity key.
 *   2. {@link SuccessorRecord} linking the prior identity key to the
 *      new one, with `recovery_signature` and `new_key_signature`
 *      populated. The home server fills in `domain_signature` on
 *      receipt per RECOVERY.md §7.3.
 *   3. New identity + new encryption public keys, fresh and ready to
 *      publish via the account's key endpoint.
 *   4. {@link RevocationPublication} for the prior identity key,
 *      reason `key_compromise`, `replacement_key_id` pointing at the
 *      new identity key, signed by the prior identity key (which the
 *      revoking device still holds).
 *
 * The home server runs {@link verifyCompromiseRotation} on receipt,
 * then commits all four artifacts atomically.
 *
 * @module
 */

import {
  type SuccessorRecord,
  RecordVersion as RecoveryRecordVersion,
  SuccessorRecordType,
  prepareSuccessorSignatures,
  signSuccessorNewKey,
  signSuccessorRecovery,
  verifySuccessorTwoSignatures,
} from "../recovery/index.js";

import {
  type DeviceRevocation,
  DeviceRecordVersion,
  DeviceRevocationType,
  signDeviceRevocation,
  verifyDeviceRevocation,
} from "./device_records.js";

import {
  type RevocationPublication,
  type RevokedKeyEntry,
  RevocationPublicationType,
  RevocationVersion,
  signRevocationPublication,
  verifyRevocationPublication,
} from "./key_revocation.js";

/**
 * The four-artifact bundle a revoking device produces for the
 * KEY.md §10.5.5 atomic identity-key rotation cascade.
 *
 * The home server MUST treat the bundle atomically: either every
 * artifact lands or none of them do.
 */
export interface CompromiseRotation {
  device_revocation: DeviceRevocation;
  successor: SuccessorRecord;
  /** Raw bytes of the new identity public key. */
  new_identity_public_key: Uint8Array;
  new_identity_key_id: string;
  /** Raw bytes of the new encryption public key. */
  new_encryption_public_key: Uint8Array;
  new_encryption_key_id: string;
  prior_identity_revocation: RevocationPublication;
}

/**
 * Inputs to {@link buildCompromiseRotation}. The caller is
 * responsible for generating the new keys (typically with a
 * fresh Ed25519 / X25519 / Kyber768 key pair) and for deriving
 * the recovery signing key from the user's recovery secret per
 * RECOVERY.md §3.3.
 */
export interface CompromiseRotationInput {
  /** Account's full SEMP address. */
  userId: string;
  /** Device being revoked. */
  compromisedDeviceId: string;
  /** Device producing the cascade - recorded as `revoked_by_device_id`. */
  revokingDeviceId: string;

  /** 32-byte Ed25519 seed for the prior identity key. */
  priorIdentitySeed: Uint8Array;
  priorIdentityKeyId: string;

  /** 32-byte Ed25519 seed for the new identity key. */
  newIdentitySeed: Uint8Array;
  /** Raw public bytes of the new identity key. */
  newIdentityPublicKey: Uint8Array;
  newIdentityKeyId: string;

  /**
   * Raw public bytes of the new encryption key. Only the public half
   * is needed in the cascade; the private half is sync'd to remaining
   * full-access devices via the device-sync channel per §10.5.5
   * step 5.
   */
  newEncryptionPublicKey: Uint8Array;
  newEncryptionKeyId: string;

  /**
   * 32-byte Ed25519 seed of the recovery signing key derived from the
   * user's recovery secret per RECOVERY.md §3.3. Signs the successor
   * record's `recovery_signature`.
   */
  recoverySeed: Uint8Array;
  recoveryKeyId: string;

  /** Wall-clock used to stamp `revoked_at` and `recovered_at`. Defaults to `new Date()`. */
  now?: Date;
}

/**
 * Produce the four-artifact bundle a revoking device submits to the
 * home server atomically.
 *
 * The successor record's `domain_signature` is left empty; the home
 * server adds it on receipt per RECOVERY.md §7.3.
 *
 * Throws on missing input or signing failure.
 */
export function buildCompromiseRotation(
  input: CompromiseRotationInput,
): CompromiseRotation {
  if (input.userId === "") {
    throw new Error("keys: rotation input missing user_id");
  }
  if (input.compromisedDeviceId === "") {
    throw new Error("keys: rotation input missing compromised_device_id");
  }
  if (input.revokingDeviceId === "") {
    throw new Error("keys: rotation input missing revoking_device_id");
  }
  if (input.priorIdentitySeed.length === 0 || input.priorIdentityKeyId === "") {
    throw new Error("keys: rotation input missing prior identity key");
  }
  if (
    input.newIdentitySeed.length === 0 ||
    input.newIdentityPublicKey.length === 0 ||
    input.newIdentityKeyId === ""
  ) {
    throw new Error("keys: rotation input missing new identity key");
  }
  if (
    input.newEncryptionPublicKey.length === 0 ||
    input.newEncryptionKeyId === ""
  ) {
    throw new Error("keys: rotation input missing new encryption key");
  }
  if (input.recoverySeed.length === 0 || input.recoveryKeyId === "") {
    throw new Error("keys: rotation input missing recovery signing key");
  }
  if (input.priorIdentityKeyId === input.newIdentityKeyId) {
    throw new Error("keys: prior and new identity fingerprints must differ");
  }

  const isoNow = isoSecond(input.now ?? new Date());

  // 1. Device revocation, reason key_compromise.
  const dev: DeviceRevocation = {
    type: DeviceRevocationType,
    version: DeviceRecordVersion,
    user_id: input.userId,
    device_id: input.compromisedDeviceId,
    reason: "key_compromise",
    revoked_at: isoNow,
    revoked_by_device_id: input.revokingDeviceId,
    replacement_device_id: null,
    signature: { algorithm: "", key_id: "", value: "" },
  };
  signDeviceRevocation(dev, input.priorIdentitySeed, input.priorIdentityKeyId);

  // 2. Successor record (recovery + new_key sigs); domain_signature
  // slot's key_id is left empty for the home server to fill in.
  const suc: SuccessorRecord = {
    type: SuccessorRecordType,
    version: RecoveryRecordVersion,
    user_id: input.userId,
    prior_key_id: input.priorIdentityKeyId,
    new_key_id: input.newIdentityKeyId,
    new_public_key: base64Encode(input.newIdentityPublicKey),
    recovered_at: isoNow,
    recovery_signature: { algorithm: "", key_id: "", value: "" },
    new_key_signature: { algorithm: "", key_id: "", value: "" },
    domain_signature: { algorithm: "", key_id: "", value: "" },
  };
  prepareSuccessorSignatures(
    suc,
    input.recoveryKeyId,
    input.newIdentityKeyId,
    "",
  );
  signSuccessorRecovery(suc, input.recoverySeed, input.recoveryKeyId);
  signSuccessorNewKey(suc, input.newIdentitySeed, input.newIdentityKeyId);

  // 3. The new public keys travel alongside the cascade; publication
  // via the key endpoint is the home server's job.

  // 4. Prior-identity revocation, signed by the prior identity key
  // with reason key_compromise and replacement_key_id pointing at the
  // new identity key.
  const priorEntry: RevokedKeyEntry = {
    key_id: input.priorIdentityKeyId,
    address: input.userId,
    reason: "key_compromise",
    revoked_at: isoNow,
    replacement_key_id: input.newIdentityKeyId,
  };
  const prior: RevocationPublication = {
    type: RevocationPublicationType,
    version: RevocationVersion,
    revoked_keys: [priorEntry],
    signature: { algorithm: "", key_id: "", value: "" },
  };
  signRevocationPublication(
    prior,
    input.priorIdentitySeed,
    input.priorIdentityKeyId,
  );

  return {
    device_revocation: dev,
    successor: suc,
    new_identity_public_key: input.newIdentityPublicKey,
    new_identity_key_id: input.newIdentityKeyId,
    new_encryption_public_key: input.newEncryptionPublicKey,
    new_encryption_key_id: input.newEncryptionKeyId,
    prior_identity_revocation: prior,
  };
}

/**
 * Verify every device-side signature in the cascade. The home server
 * runs this on receipt before committing the bundle, then adds its
 * own `domain_signature` to the successor record per RECOVERY.md §7.3.
 *
 * Throws on the first violation.
 *
 * @param c - the bundle
 * @param priorIdentityPub - published public half of the prior
 *   identity key (the home server resolves it from the account's
 *   now-revoked-but-historical key set)
 * @param recoveryVerifyPub - the `recovery_verify_pk` that the prior
 *   identity key signed at bundle upload time per RECOVERY.md §7.5
 *   (the home server resolves it from the prior key record)
 */
export function verifyCompromiseRotation(
  c: CompromiseRotation,
  priorIdentityPub: Uint8Array,
  recoveryVerifyPub: Uint8Array,
): void {
  if (c.device_revocation === undefined || c.device_revocation === null) {
    throw new Error("keys: rotation bundle missing device_revocation");
  }
  if (c.successor === undefined || c.successor === null) {
    throw new Error("keys: rotation bundle missing successor record");
  }
  if (
    c.prior_identity_revocation === undefined ||
    c.prior_identity_revocation === null
  ) {
    throw new Error("keys: rotation bundle missing prior_identity_revocation");
  }
  if (c.device_revocation.reason !== "key_compromise") {
    throw new Error(
      `keys: rotation device revocation reason ${JSON.stringify(c.device_revocation.reason)}, want key_compromise`,
    );
  }
  if (!verifyDeviceRevocation(c.device_revocation, priorIdentityPub)) {
    throw new Error("keys: device revocation signature did not verify");
  }
  // Successor record: recovery_signature verifies under
  // recoveryVerifyPub; new_key_signature verifies under the new
  // identity public key carried inline in new_public_key;
  // domain_signature is empty at this point.
  let newPub: Uint8Array;
  try {
    newPub = base64Decode(c.successor.new_public_key);
  } catch (err) {
    throw new Error(
      `keys: decode successor new_public_key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!verifySuccessorTwoSignatures(c.successor, recoveryVerifyPub, newPub)) {
    throw new Error("keys: successor record two-signature verify failed");
  }
  if (
    !verifyRevocationPublication(
      c.prior_identity_revocation,
      priorIdentityPub,
    )
  ) {
    throw new Error(
      "keys: prior identity revocation signature did not verify",
    );
  }
  // Cross-check: the revocation entry MUST name the prior identity
  // key with reason key_compromise and replacement = new identity key
  // carried inline.
  if (c.prior_identity_revocation.revoked_keys.length !== 1) {
    throw new Error(
      `keys: prior identity revocation MUST contain exactly one entry, got ${c.prior_identity_revocation.revoked_keys.length}`,
    );
  }
  const entry = c.prior_identity_revocation.revoked_keys[0]!;
  if (entry.reason !== "key_compromise") {
    throw new Error(
      `keys: prior identity revocation entry reason ${JSON.stringify(entry.reason)}, want key_compromise`,
    );
  }
  if (entry.replacement_key_id !== c.new_identity_key_id) {
    throw new Error(
      `keys: prior identity revocation replacement ${JSON.stringify(entry.replacement_key_id)} does not match cascade new_identity_key_id ${JSON.stringify(c.new_identity_key_id)}`,
    );
  }
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
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
