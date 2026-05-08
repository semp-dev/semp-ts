/**
 * Multi-device record primitives per KEY.md §10.1, §10.5, §10.6.
 *
 * Three record kinds share an account-identity-key signature on the
 * outer envelope so a home server or correspondent can verify
 * "this record was authored by the account's current identity key"
 * without knowing the device graph in advance:
 *
 *   - {@link DeviceRegistration} (`SEMP_DEVICE`, step="register"):
 *     announces a new device. Carries device pubkey, role, and an
 *     INNER authorization signature from an existing full-access
 *     device that authorized the enrollment (§10.2).
 *   - {@link DeviceRevocation} (`SEMP_DEVICE_REVOCATION`): removes
 *     a device from the active set per §10.5.
 *   - {@link DeviceDirectory} (`SEMP_DEVICE_DIRECTORY`): the
 *     home server's signed list of currently active devices, with
 *     a monotonically increasing revision so correspondents can
 *     detect rollback per §10.6.
 *
 * The SEMP_DEVICE_CERTIFICATE (scoped delegation) lives in
 * {@link "./device_certificate"}.
 *
 * @module
 */

import { sign as ed25519Sign, verify as ed25519Verify } from "./sign.js";
import { signSignedDoc, verifySignedDoc } from "./signed.js";

/** Wire-level type discriminators. */
export const DeviceRegistrationType = "SEMP_DEVICE";
export const DeviceRegistrationStep = "register";
export const DeviceRevocationType = "SEMP_DEVICE_REVOCATION";
export const DeviceDirectoryType = "SEMP_DEVICE_DIRECTORY";
export const DeviceRecordVersion = "1.0.0";

/** Domain-separation prefixes per ENVELOPE.md §4.3. */
export const DeviceRegisterPrefix = "SEMP-DEVICE-REGISTER:";
export const DeviceAuthorizeRecordPrefix = "SEMP-DEVICE-AUTHORIZE:";
export const DeviceRevocationPrefix = "SEMP-DEVICE-REVOCATION:";
export const DeviceDirectoryPrefix = "SEMP-DEVICE-DIRECTORY:";

/** Device authority levels per §10.1. */
export type DeviceRole = "full_access" | "delegated";

/** Authorization methods per §10.2.1. */
export type DeviceAuthorizationMethod = "qr_scan" | "numeric_code";

/** Reasons a device may be revoked per §10.5.2. */
export type DeviceRevocationReason =
  | "key_compromise"
  | "lost"
  | "retired"
  | "superseded";

/**
 * Report whether `r` is the kind of revocation that triggers
 * mandatory identity-key rotation per §10.5.5.
 */
export function requiresIdentityRotation(r: DeviceRevocationReason): boolean {
  return r === "key_compromise";
}

/** Reusable signature block. */
export interface KeysSignature {
  algorithm: string;
  key_id: string;
  value: string;
}

/** Inner authorization block embedded in a {@link DeviceRegistration}. */
export interface DeviceAuthorization {
  method: DeviceAuthorizationMethod;
  authorizing_device_id: string;
  authorizing_signature: KeysSignature;
}

/** SEMP_DEVICE register record per §10.1. */
export interface DeviceRegistration {
  type: typeof DeviceRegistrationType;
  step: typeof DeviceRegistrationStep;
  version: string;
  user_id: string;
  device_id: string;
  device_name: string;
  device_type: string;
  device_public_key: string;
  device_identity_pubkey_algorithm: string;
  /** ISO 8601 UTC. */
  enrolled_at: string;
  role: DeviceRole;
  /** For `delegated`: matches a SEMP_DEVICE_CERTIFICATE device_id. For `full_access`: null. */
  certificate_id: string | null;
  authorization: DeviceAuthorization;
  signature: KeysSignature;
}

/** SEMP_DEVICE_REVOCATION record per §10.5.1. */
export interface DeviceRevocation {
  type: typeof DeviceRevocationType;
  version: string;
  user_id: string;
  device_id: string;
  reason: DeviceRevocationReason;
  /** ISO 8601 UTC. */
  revoked_at: string;
  revoked_by_device_id: string;
  /** Non-null only for reason="superseded". */
  replacement_device_id: string | null;
  signature: KeysSignature;
}

/** One entry inside a {@link DeviceDirectory} per §10.6.1. */
export interface DeviceDirectoryEntry {
  device_id: string;
  device_public_key: string;
  device_identity_pubkey_algorithm: string;
  role: DeviceRole;
  certificate_id: string | null;
  /** ISO 8601 UTC. */
  enrolled_at: string;
  device_name: string;
  device_type: string;
}

/** SEMP_DEVICE_DIRECTORY record per §10.6.1. */
export interface DeviceDirectory {
  type: typeof DeviceDirectoryType;
  version: string;
  user_id: string;
  /** Monotonically non-decreasing per emission. */
  revision: number;
  /** ISO 8601 UTC. */
  issued_at: string;
  devices: DeviceDirectoryEntry[];
  signature: KeysSignature;
}

// ---------------------------------------------------------------------------
// Inner authorization signature (raw bytes, NOT canonical JSON)

/**
 * Inputs to {@link signDeviceAuthorization}. The signature covers the
 * length-prefixed (NUL-separated) concatenation of
 * `device_id || device_public_key || enrolled_at || enroll_nonce`,
 * prefixed with `SEMP-DEVICE-AUTHORIZE:`.
 */
export interface SignDeviceAuthorizationInput {
  /** The half-built registration; `authorization` will be replaced. */
  registration: DeviceRegistration;
  /** 32-byte Ed25519 secret seed for the authorizing full-access device. */
  authorizingDeviceSeed: Uint8Array;
  /** Stable id of the authorizing device. */
  authorizingDeviceId: string;
  /** Lowercase-hex SHA-256 fingerprint of the authorizing device pub. */
  authorizingDeviceKeyId: string;
  /** Fresh 32-byte enrollment nonce (single-use per attempt). */
  enrollNonce: Uint8Array;
  /** `qr_scan` or `numeric_code`. */
  method: DeviceAuthorizationMethod;
}

/**
 * Sign the inner authorization block and place it on
 * `registration.authorization`. The caller MUST have populated
 * `registration.device_id`, `device_public_key`, `enrolled_at`
 * before calling.
 */
export function signDeviceAuthorization(
  input: SignDeviceAuthorizationInput,
): void {
  const reg = input.registration;
  if (input.enrollNonce.length === 0) {
    throw new Error("keys: empty enroll nonce");
  }
  if (input.authorizingDeviceId === "") {
    throw new Error("keys: empty authorizing_device_id");
  }
  if (input.authorizingDeviceKeyId === "") {
    throw new Error("keys: empty authorizing key_id");
  }
  if (reg.device_id === "" || reg.device_public_key === "" || reg.enrolled_at === "") {
    throw new Error(
      "keys: device registration missing device_id / device_public_key / enrolled_at",
    );
  }
  const authBytes = authorizationCanonicalBytes(
    reg.device_id,
    reg.device_public_key,
    reg.enrolled_at,
    input.enrollNonce,
  );
  const prefixed = concat(
    new TextEncoder().encode(DeviceAuthorizeRecordPrefix),
    authBytes,
  );
  const sig = ed25519Sign(input.authorizingDeviceSeed, prefixed);
  reg.authorization = {
    method: input.method,
    authorizing_device_id: input.authorizingDeviceId,
    authorizing_signature: {
      algorithm: "ed25519",
      key_id: input.authorizingDeviceKeyId,
      value: base64Encode(sig),
    },
  };
}

/**
 * Verify the inner authorizing-device signature on `registration`
 * using the supplied authorizing-device public key and the SAME
 * `enrollNonce` that was used at sign time. Returns true on success.
 */
export function verifyDeviceAuthorization(
  registration: DeviceRegistration,
  authorizingDevicePub: Uint8Array,
  enrollNonce: Uint8Array,
): boolean {
  const sigB64 = registration.authorization?.authorizing_signature?.value;
  if (typeof sigB64 !== "string" || sigB64 === "") {
    return false;
  }
  let sig: Uint8Array;
  try {
    sig = base64Decode(sigB64);
  } catch {
    return false;
  }
  const authBytes = authorizationCanonicalBytes(
    registration.device_id,
    registration.device_public_key,
    registration.enrolled_at,
    enrollNonce,
  );
  const prefixed = concat(
    new TextEncoder().encode(DeviceAuthorizeRecordPrefix),
    authBytes,
  );
  return ed25519Verify(authorizingDevicePub, sig, prefixed);
}

function authorizationCanonicalBytes(
  deviceId: string,
  devicePublicKey: string,
  enrolledAt: string,
  enrollNonce: Uint8Array,
): Uint8Array {
  // Per semp-go: NUL-separated concatenation. Boundaries are
  // unambiguous because none of the three string components can
  // contain a NUL byte under SEMP rules.
  const parts: Uint8Array[] = [
    new TextEncoder().encode(deviceId),
    new Uint8Array([0]),
    new TextEncoder().encode(devicePublicKey),
    new Uint8Array([0]),
    new TextEncoder().encode(enrolledAt),
    new Uint8Array([0]),
    enrollNonce,
  ];
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Outer registration signature (canonical JSON)

/** Sign the outer identity-key signature on a registration record. */
export function signDeviceRegistration(
  reg: DeviceRegistration,
  identityPriv: Uint8Array,
  identityKeyId: string,
): string {
  if (identityKeyId === "") {
    throw new Error("keys: empty identity key_id");
  }
  validateDeviceRegistration(reg, { skipSignatureCheck: true });
  reg.signature.algorithm = "ed25519";
  reg.signature.key_id = identityKeyId;
  reg.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: reg as unknown as Record<string, unknown>,
    seed: identityPriv,
    signaturePath: "signature.value",
    prefix: DeviceRegisterPrefix,
  });
  reg.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify the outer identity-key signature on a registration record. */
export function verifyDeviceRegistration(
  reg: DeviceRegistration,
  identityPub: Uint8Array,
): boolean {
  validateDeviceRegistration(reg);
  if (reg.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: reg as unknown as Record<string, unknown>,
    publicKey: identityPub,
    signaturePath: "signature.value",
    prefix: DeviceRegisterPrefix,
  });
  return ok;
}

/** Structural validation per §10.1. Throws on first violation. */
export function validateDeviceRegistration(
  reg: DeviceRegistration,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (reg.type !== DeviceRegistrationType) {
    throw new Error(
      `keys: device registration type ${JSON.stringify(reg.type)}, want ${DeviceRegistrationType}`,
    );
  }
  if (reg.step !== DeviceRegistrationStep) {
    throw new Error(
      `keys: device registration step ${JSON.stringify(reg.step)}, want ${DeviceRegistrationStep}`,
    );
  }
  for (const f of [
    "version",
    "user_id",
    "device_id",
    "device_name",
    "device_type",
    "device_public_key",
    "device_identity_pubkey_algorithm",
    "enrolled_at",
  ] as const) {
    if (typeof reg[f] !== "string" || reg[f] === "") {
      throw new Error(`keys: device registration missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(reg.enrolled_at))) {
    throw new Error("keys: device registration enrolled_at is not ISO 8601");
  }
  if (reg.role !== "full_access" && reg.role !== "delegated") {
    throw new Error(
      `keys: device registration role ${JSON.stringify(reg.role)} is invalid`,
    );
  }
  if (reg.role === "full_access" && reg.certificate_id !== null) {
    throw new Error("keys: device registration role=full_access requires certificate_id=null");
  }
  if (reg.role === "delegated") {
    if (reg.certificate_id === null || reg.certificate_id === "") {
      throw new Error(
        "keys: device registration role=delegated requires non-empty certificate_id",
      );
    }
  }
  if (reg.authorization === undefined || reg.authorization === null) {
    throw new Error("keys: device registration missing authorization");
  }
  if (
    reg.authorization.method !== "qr_scan" &&
    reg.authorization.method !== "numeric_code"
  ) {
    throw new Error(
      `keys: device registration authorization.method ${JSON.stringify(reg.authorization.method)} is invalid`,
    );
  }
  if (
    typeof reg.authorization.authorizing_device_id !== "string" ||
    reg.authorization.authorizing_device_id === ""
  ) {
    throw new Error("keys: device registration missing authorization.authorizing_device_id");
  }
  if (typeof reg.authorization.authorizing_signature?.value !== "string") {
    throw new Error("keys: device registration missing authorization.authorizing_signature.value");
  }
  if (typeof reg.signature?.algorithm !== "string") {
    throw new Error("keys: device registration missing signature.algorithm");
  }
  if (typeof reg.signature?.key_id !== "string") {
    throw new Error("keys: device registration missing signature.key_id");
  }
  if (typeof reg.signature?.value !== "string") {
    throw new Error("keys: device registration signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && reg.signature.value === "") {
    throw new Error("keys: device registration is unsigned");
  }
}

// ---------------------------------------------------------------------------
// DeviceRevocation

/** Sign the identity-key signature on a device revocation record. */
export function signDeviceRevocation(
  rev: DeviceRevocation,
  identityPriv: Uint8Array,
  identityKeyId: string,
): string {
  if (identityKeyId === "") {
    throw new Error("keys: empty identity key_id");
  }
  validateDeviceRevocation(rev, { skipSignatureCheck: true });
  rev.signature.algorithm = "ed25519";
  rev.signature.key_id = identityKeyId;
  rev.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: rev as unknown as Record<string, unknown>,
    seed: identityPriv,
    signaturePath: "signature.value",
    prefix: DeviceRevocationPrefix,
  });
  rev.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify a device revocation record. */
export function verifyDeviceRevocation(
  rev: DeviceRevocation,
  identityPub: Uint8Array,
): boolean {
  validateDeviceRevocation(rev);
  if (rev.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: rev as unknown as Record<string, unknown>,
    publicKey: identityPub,
    signaturePath: "signature.value",
    prefix: DeviceRevocationPrefix,
  });
  return ok;
}

/** Structural validation per §10.5.1. Throws on first violation. */
export function validateDeviceRevocation(
  rev: DeviceRevocation,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (rev.type !== DeviceRevocationType) {
    throw new Error(
      `keys: device revocation type ${JSON.stringify(rev.type)}, want ${DeviceRevocationType}`,
    );
  }
  for (const f of ["version", "user_id", "device_id", "revoked_at", "revoked_by_device_id"] as const) {
    if (typeof rev[f] !== "string" || rev[f] === "") {
      throw new Error(`keys: device revocation missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(rev.revoked_at))) {
    throw new Error("keys: device revocation revoked_at is not ISO 8601");
  }
  if (
    rev.reason !== "key_compromise" &&
    rev.reason !== "lost" &&
    rev.reason !== "retired" &&
    rev.reason !== "superseded"
  ) {
    throw new Error(
      `keys: device revocation reason ${JSON.stringify(rev.reason)} is invalid`,
    );
  }
  if (rev.reason === "superseded") {
    if (rev.replacement_device_id === null || rev.replacement_device_id === "") {
      throw new Error(
        "keys: device revocation reason=superseded requires replacement_device_id",
      );
    }
  } else if (rev.replacement_device_id !== null) {
    throw new Error(
      `keys: device revocation reason=${rev.reason} forbids replacement_device_id`,
    );
  }
  if (typeof rev.signature?.value !== "string") {
    throw new Error("keys: device revocation signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && rev.signature.value === "") {
    throw new Error("keys: device revocation is unsigned");
  }
}

// ---------------------------------------------------------------------------
// DeviceDirectory

/** Sign the identity-key signature on a device directory record. */
export function signDeviceDirectory(
  dir: DeviceDirectory,
  identityPriv: Uint8Array,
  identityKeyId: string,
): string {
  if (identityKeyId === "") {
    throw new Error("keys: empty identity key_id");
  }
  validateDeviceDirectory(dir, { skipSignatureCheck: true });
  dir.signature.algorithm = "ed25519";
  dir.signature.key_id = identityKeyId;
  dir.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: dir as unknown as Record<string, unknown>,
    seed: identityPriv,
    signaturePath: "signature.value",
    prefix: DeviceDirectoryPrefix,
  });
  dir.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify a device directory record. */
export function verifyDeviceDirectory(
  dir: DeviceDirectory,
  identityPub: Uint8Array,
): boolean {
  validateDeviceDirectory(dir);
  if (dir.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: dir as unknown as Record<string, unknown>,
    publicKey: identityPub,
    signaturePath: "signature.value",
    prefix: DeviceDirectoryPrefix,
  });
  return ok;
}

/** Structural validation per §10.6.1. Throws on first violation. */
export function validateDeviceDirectory(
  dir: DeviceDirectory,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (dir.type !== DeviceDirectoryType) {
    throw new Error(
      `keys: device directory type ${JSON.stringify(dir.type)}, want ${DeviceDirectoryType}`,
    );
  }
  for (const f of ["version", "user_id", "issued_at"] as const) {
    if (typeof dir[f] !== "string" || dir[f] === "") {
      throw new Error(`keys: device directory missing ${f}`);
    }
  }
  if (!Number.isInteger(dir.revision) || dir.revision < 0) {
    throw new Error(`keys: device directory revision ${dir.revision} MUST be >= 0`);
  }
  if (Number.isNaN(Date.parse(dir.issued_at))) {
    throw new Error("keys: device directory issued_at is not ISO 8601");
  }
  if (!Array.isArray(dir.devices)) {
    throw new Error("keys: device directory devices must be an array");
  }
  const seenIds = new Set<string>();
  for (let i = 0; i < dir.devices.length; i++) {
    const d = dir.devices[i]!;
    for (const f of [
      "device_id",
      "device_public_key",
      "device_identity_pubkey_algorithm",
      "enrolled_at",
      "device_name",
      "device_type",
    ] as const) {
      if (typeof d[f] !== "string" || d[f] === "") {
        throw new Error(`keys: device directory devices[${i}] missing ${f}`);
      }
    }
    if (seenIds.has(d.device_id)) {
      throw new Error(
        `keys: device directory device_id ${JSON.stringify(d.device_id)} appears more than once`,
      );
    }
    seenIds.add(d.device_id);
    if (d.role !== "full_access" && d.role !== "delegated") {
      throw new Error(
        `keys: device directory devices[${i}] role ${JSON.stringify(d.role)} is invalid`,
      );
    }
    if (d.role === "full_access" && d.certificate_id !== null) {
      throw new Error(
        `keys: device directory devices[${i}] role=full_access requires certificate_id=null`,
      );
    }
    if (d.role === "delegated") {
      if (d.certificate_id === null || d.certificate_id === "") {
        throw new Error(
          `keys: device directory devices[${i}] role=delegated requires non-empty certificate_id`,
        );
      }
    }
  }
  if (typeof dir.signature?.value !== "string") {
    throw new Error("keys: device directory signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && dir.signature.value === "") {
    throw new Error("keys: device directory is unsigned");
  }
}

/** Look up a device entry by id. Returns null when not found. */
export function findDevice(
  dir: DeviceDirectory,
  deviceId: string,
): DeviceDirectoryEntry | null {
  for (const d of dir.devices) {
    if (d.device_id === deviceId) {
      return d;
    }
  }
  return null;
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
