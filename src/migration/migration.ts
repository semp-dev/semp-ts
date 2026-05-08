/**
 * Cooperative migration record compose per MIGRATION.md §3.
 *
 * A migration record carries four signatures. Each signer's bytes
 * are computed over a canonical record where every PRIOR signer's
 * value is populated and every LATER signer's value is "" — a
 * cumulative chain that prevents reordering.
 *
 * Chain order:
 *   1. old_identity_signature
 *   2. new_identity_signature
 *   3. new_domain_signature
 *   4. old_domain_signature
 *
 * The verify path replays this same blanking sequence; semp-ts
 * already exercises it in the vectors-runner.
 *
 * @module
 */

import { sign as ed25519Sign } from "../keys/index.js";
import { marshal as canonicalMarshal } from "../canonical/index.js";

/** Domain-separation prefix per ENVELOPE.md §4.3. */
export const MigrationPrefix = "SEMP-MIGRATION-RECORD:";

/** A signature block as it appears in the wire record. */
interface SigBlock {
  algorithm: "ed25519";
  key_id: string;
  value: string;
}

/** Inputs to {@link composeMigrationRecord}. */
export interface ComposeMigrationInput {
  /** Migration mode (e.g. "cooperative"). */
  mode: string;
  /** ULID for the migration record. */
  recordId: string;
  /** ISO 8601 timestamp the migration was effected. */
  migratedAt: string;
  /** ISO 8601 timestamp until which the old domain forwards mail. */
  forwardingWindowUntil: string;
  /** Old SEMP address (`alice@old.example`). */
  oldAddress: string;
  /** New SEMP address (`alice@new.example`). */
  newAddress: string;

  /** Old identity key fingerprint (key_id). */
  oldIdentityKeyId: string;
  /** Old identity 32-byte Ed25519 secret seed. */
  oldIdentitySeed: Uint8Array;

  /** New identity key fingerprint. */
  newIdentityKeyId: string;
  /** Base64-encoded new identity public key (advertised in the record). */
  newIdentityPublicKey: string;
  /** New identity 32-byte Ed25519 secret seed. */
  newIdentitySeed: Uint8Array;

  /** Old domain signing fingerprint. */
  oldDomainKeyId: string;
  /** Old domain 32-byte Ed25519 secret seed. */
  oldDomainSeed: Uint8Array;

  /** New domain signing fingerprint. */
  newDomainKeyId: string;
  /** New domain 32-byte Ed25519 secret seed. */
  newDomainSeed: Uint8Array;

  /** Optional extensions block. */
  extensions?: Record<string, unknown>;
}

/**
 * Compose a fully-signed migration record. The four signatures are
 * applied in chain order; each step canonicalizes the record with
 * the appropriate blanking and Ed25519-signs it under the
 * SEMP-MIGRATION-RECORD: prefix.
 */
export function composeMigrationRecord(input: ComposeMigrationInput): Record<string, unknown> {
  // Build the record skeleton with all four signature blocks set
  // to placeholders. Subsequent steps mutate this object in place.
  const record: Record<string, unknown> = {
    type: "SEMP_MIGRATION",
    version: "1.0.0",
    record_id: input.recordId,
    mode: input.mode,
    old_address: input.oldAddress,
    new_address: input.newAddress,
    migrated_at: input.migratedAt,
    forwarding_window_until: input.forwardingWindowUntil,
    old_identity_key_id: input.oldIdentityKeyId,
    new_identity_key_id: input.newIdentityKeyId,
    new_identity_public_key: input.newIdentityPublicKey,
    extensions: input.extensions ?? {},
    old_identity_signature: blank("ed25519", input.oldIdentityKeyId),
    new_identity_signature: blank("ed25519", input.newIdentityKeyId),
    new_domain_signature: blank("ed25519", input.newDomainKeyId),
    old_domain_signature: blank("ed25519", input.oldDomainKeyId),
  };

  // Chain order: each step blanks ITSELF and every LATER signer,
  // leaves PRIOR signers populated.
  const chain: Array<{
    field: string;
    seed: Uint8Array;
  }> = [
    { field: "old_identity_signature", seed: input.oldIdentitySeed },
    { field: "new_identity_signature", seed: input.newIdentitySeed },
    { field: "new_domain_signature", seed: input.newDomainSeed },
    { field: "old_domain_signature", seed: input.oldDomainSeed },
  ];

  for (let i = 0; i < chain.length; i++) {
    // Blank step[i] and every step[j>i]; leave step[j<i] populated.
    const view = JSON.parse(JSON.stringify(record)) as Record<string, unknown>;
    for (let j = i; j < chain.length; j++) {
      const step = chain[j];
      if (step === undefined) {
        continue;
      }
      const obj = view[step.field] as Record<string, unknown>;
      obj.value = "";
    }
    const canonical = canonicalMarshal(view);
    const signingInput = concat(new TextEncoder().encode(MigrationPrefix), canonical);
    const me = chain[i];
    if (me === undefined) {
      continue;
    }
    const sig = ed25519Sign(me.seed, signingInput);
    const block = record[me.field] as Record<string, unknown>;
    block.value = base64Encode(sig);
  }

  return record;
}

function blank(algorithm: "ed25519", keyId: string): SigBlock {
  return { algorithm, key_id: keyId, value: "" };
}

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
