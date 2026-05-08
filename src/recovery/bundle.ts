/**
 * SEMP_BACKUP_BUNDLE sign / verify primitives per RECOVERY.md §2.
 *
 * Covers the wire shape and identity-key signature over the bundle.
 * Payload encryption (Argon2id-derived key + XChaCha20-Poly1305) is
 * the next layer up; this module ships the record-level primitives
 * the higher-level flow plugs into.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

import {
  type BackupBundle,
  KDFAlgorithmArgon2id,
  MinKDFIterations,
  MinKDFMemoryKB,
  MinKDFParallelism,
  MinKDFSaltBytes,
  RecoveryBundlePrefix,
  SignatureAlgorithmEd25519,
} from "./types.js";

/**
 * Sign `b.signature` with the user's currently active identity
 * private key per §2.4.
 */
export function signBundle(
  b: BackupBundle,
  identityPriv: Uint8Array,
  identityKeyId: string,
): string {
  if (identityKeyId === "") {
    throw new Error("recovery: empty identity key_id");
  }
  validateBundle(b, { skipSignatureCheck: true });
  b.signature.algorithm = SignatureAlgorithmEd25519;
  b.signature.key_id = identityKeyId;
  b.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: b as unknown as Record<string, unknown>,
    seed: identityPriv,
    signaturePath: "signature.value",
    prefix: RecoveryBundlePrefix,
  });
  b.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify `b.signature` against `identityPub`. */
export function verifyBundle(
  b: BackupBundle,
  identityPub: Uint8Array,
): boolean {
  validateBundle(b);
  if (b.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: b as unknown as Record<string, unknown>,
    publicKey: identityPub,
    signaturePath: "signature.value",
    prefix: RecoveryBundlePrefix,
  });
  return ok;
}

/**
 * Structural validation per §2.1 + §2.5. Throws on the first
 * violation. Enforces:
 *
 *  - Required string fields present.
 *  - `kdf.algorithm === "argon2id"` (the only KDF currently spec'd).
 *  - Argon2id parameter floors: memory_kb >= 65536, iterations >= 2,
 *    parallelism >= 1, salt >= 16 bytes (after base64 decode).
 *  - `payload_algorithm === "xchacha20-poly1305"`.
 *  - `signature.{algorithm,key_id,value}` present (value optional
 *    when `skipSignatureCheck`).
 */
export function validateBundle(
  b: BackupBundle,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (b.type !== "SEMP_BACKUP_BUNDLE") {
    throw new Error(
      `recovery: bundle type ${JSON.stringify(b.type)}, want SEMP_BACKUP_BUNDLE`,
    );
  }
  for (const f of [
    "version",
    "user_id",
    "bundle_id",
    "created_at",
    "payload_algorithm",
    "payload_nonce",
    "encrypted_payload",
  ] as const) {
    if (typeof b[f] !== "string" || b[f] === "") {
      throw new Error(`recovery: bundle missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(b.created_at))) {
    throw new Error("recovery: bundle created_at is not ISO 8601");
  }
  if (b.payload_algorithm !== "xchacha20-poly1305") {
    throw new Error(
      `recovery: bundle payload_algorithm ${JSON.stringify(b.payload_algorithm)}, want xchacha20-poly1305`,
    );
  }
  if (b.kdf === undefined || b.kdf === null) {
    throw new Error("recovery: bundle missing kdf");
  }
  if (b.kdf.algorithm !== KDFAlgorithmArgon2id) {
    throw new Error(
      `recovery: bundle kdf.algorithm ${JSON.stringify(b.kdf.algorithm)}, want ${KDFAlgorithmArgon2id}`,
    );
  }
  if (typeof b.kdf.salt !== "string" || b.kdf.salt === "") {
    throw new Error("recovery: bundle kdf.salt missing");
  }
  // Decode the salt to enforce the 16-byte floor.
  const saltBytes = base64Decode(b.kdf.salt);
  if (saltBytes.length < MinKDFSaltBytes) {
    throw new Error(
      `recovery: bundle kdf.salt ${saltBytes.length} bytes below minimum ${MinKDFSaltBytes}`,
    );
  }
  if (
    !Number.isInteger(b.kdf.memory_kb) ||
    b.kdf.memory_kb < MinKDFMemoryKB
  ) {
    throw new Error(
      `recovery: bundle kdf.memory_kb ${b.kdf.memory_kb} below minimum ${MinKDFMemoryKB}`,
    );
  }
  if (
    !Number.isInteger(b.kdf.iterations) ||
    b.kdf.iterations < MinKDFIterations
  ) {
    throw new Error(
      `recovery: bundle kdf.iterations ${b.kdf.iterations} below minimum ${MinKDFIterations}`,
    );
  }
  if (
    !Number.isInteger(b.kdf.parallelism) ||
    b.kdf.parallelism < MinKDFParallelism
  ) {
    throw new Error(
      `recovery: bundle kdf.parallelism ${b.kdf.parallelism} below minimum ${MinKDFParallelism}`,
    );
  }
  if (
    b.recovery_verify_pk === undefined ||
    typeof b.recovery_verify_pk?.public_key !== "string" ||
    b.recovery_verify_pk.public_key === ""
  ) {
    throw new Error("recovery: bundle recovery_verify_pk.public_key missing");
  }
  if (typeof b.recovery_verify_pk.algorithm !== "string" || b.recovery_verify_pk.algorithm === "") {
    throw new Error("recovery: bundle recovery_verify_pk.algorithm missing");
  }
  if (b.supersedes !== null && (typeof b.supersedes !== "string" || b.supersedes === "")) {
    throw new Error(
      "recovery: bundle supersedes must be a non-empty string or null",
    );
  }
  if (typeof b.signature?.algorithm !== "string") {
    throw new Error("recovery: bundle signature.algorithm missing");
  }
  if (typeof b.signature?.key_id !== "string") {
    throw new Error("recovery: bundle signature.key_id missing");
  }
  if (typeof b.signature?.value !== "string") {
    throw new Error("recovery: bundle signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && b.signature.value === "") {
    throw new Error("recovery: bundle is unsigned");
  }
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
