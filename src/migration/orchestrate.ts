/**
 * Migration submission + acceptance orchestration per MIGRATION.md
 * §4.1.
 *
 * The new provider builds a 3-signature submission record and POSTs
 * it to the old provider's migration endpoint. The old provider
 * verifies the three submitted signatures, applies its forwarding
 * policy, registers the §6 lockout, countersigns, persists, and
 * returns the final 4-signature record.
 *
 * Unilateral mode skips the countersign step — the new provider's
 * 3-signature record is the final published form.
 *
 * @module
 */

import {
  type LockoutRegistry,
} from "./lockout.js";
import {
  type PublicationStore,
} from "./publication_store.js";
import {
  checkMigratedAtBound,
  prepareSignatures,
  signNewDomain,
  signNewIdentity,
  signOldDomain,
  signOldIdentity,
  validateMigrationRecord,
  verifyMigrationPass,
} from "./sign.js";
import {
  type MigrationMode,
  type MigrationRecord,
  MaxForwardingWindowMs,
  MigrationRecordType,
  MigrationRecordVersion,
  MinForwardingWindowMs,
} from "./types.js";

/** Inputs to {@link buildSubmission}. */
export interface BuildSubmissionInput {
  oldAddress: string;
  newAddress: string;
  oldIdentityKeyId: string;
  newIdentityKeyId: string;
  /** Base64-encoded new identity public key (advertised in the record body). */
  newIdentityPublicKey: string;

  oldIdentityPriv: Uint8Array;
  newIdentityPriv: Uint8Array;

  newDomainKeyId: string;
  newDomainPriv: Uint8Array;

  /** Old provider's domain signing fingerprint (cooperative only). */
  oldDomainKeyId?: string;

  mode: MigrationMode;

  /** Forwarding window in milliseconds. Cooperative mode only. */
  forwardingWindowMs?: number;

  /** ISO 8601 UTC. */
  migratedAt: string;

  /** Optional pre-assigned record_id; auto-generated when omitted. */
  recordId?: string;

  /** Random source for record id minting. */
  rand?: (n: number) => Uint8Array;
}

/**
 * Construct and apply the new-provider signatures (passes 1–3). In
 * cooperative mode the returned record's `old_domain_signature`
 * slot is prepared but empty — the new provider POSTs the record
 * to the old provider, who runs {@link acceptSubmission} to verify
 * and countersign.
 */
export function buildSubmission(
  input: BuildSubmissionInput,
): MigrationRecord {
  if (input.oldAddress === "" || input.newAddress === "") {
    throw new Error("migration: old_address and new_address are required");
  }
  if (input.oldIdentityKeyId === "" || input.newIdentityKeyId === "") {
    throw new Error(
      "migration: old_identity_key_id and new_identity_key_id are required",
    );
  }
  if (input.newIdentityPublicKey === "") {
    throw new Error("migration: new_identity_public_key is required");
  }
  if (input.newDomainKeyId === "") {
    throw new Error("migration: new_domain_key_id is required");
  }
  if (input.migratedAt === "") {
    throw new Error("migration: migrated_at is required");
  }
  if (input.mode !== "cooperative" && input.mode !== "unilateral") {
    throw new Error(`migration: unknown mode ${JSON.stringify(input.mode)}`);
  }

  let forwardingUntil: string | null = null;
  if (input.mode === "cooperative") {
    const windowMs = input.forwardingWindowMs ?? 0;
    if (windowMs < MinForwardingWindowMs) {
      throw new Error(
        `migration: forwarding window ${windowMs} below minimum ${MinForwardingWindowMs}`,
      );
    }
    if (windowMs > MaxForwardingWindowMs) {
      throw new Error(
        `migration: forwarding window ${windowMs} exceeds maximum ${MaxForwardingWindowMs}`,
      );
    }
    if (input.oldDomainKeyId === undefined || input.oldDomainKeyId === "") {
      throw new Error(
        "migration: cooperative mode requires oldDomainKeyId (looked up from the old provider's discovery configuration)",
      );
    }
    const migratedMs = Date.parse(input.migratedAt);
    if (Number.isNaN(migratedMs)) {
      throw new Error("migration: migrated_at is not ISO 8601");
    }
    forwardingUntil = new Date(migratedMs + windowMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  const recordId = input.recordId ?? newRecordID(input.rand);

  const record: MigrationRecord = {
    type: MigrationRecordType,
    version: MigrationRecordVersion,
    record_id: recordId,
    old_address: input.oldAddress,
    new_address: input.newAddress,
    old_identity_key_id: input.oldIdentityKeyId,
    new_identity_key_id: input.newIdentityKeyId,
    new_identity_public_key: input.newIdentityPublicKey,
    migrated_at: input.migratedAt,
    forwarding_window_until: forwardingUntil,
    mode: input.mode,
    old_identity_signature: { algorithm: "", key_id: "", value: "" },
    new_identity_signature: { algorithm: "", key_id: "", value: "" },
    new_domain_signature: { algorithm: "", key_id: "", value: "" },
    old_domain_signature: null,
  };

  prepareSignatures(
    record,
    input.oldIdentityKeyId,
    input.newIdentityKeyId,
    input.newDomainKeyId,
    input.oldDomainKeyId,
  );

  signOldIdentity(record, input.oldIdentityPriv, input.oldIdentityKeyId);
  signNewIdentity(record, input.newIdentityPriv, input.newIdentityKeyId);
  signNewDomain(record, input.newDomainPriv, input.newDomainKeyId);

  return record;
}

/** Inputs to {@link acceptSubmission}. */
export interface AcceptSubmissionInput {
  /** 3-signature record submitted by the new provider. */
  record: MigrationRecord;

  /** Old identity public key resolved from the old provider's prior key state. */
  oldIdentityPub: Uint8Array;

  /** New provider's current domain signing key (resolved via discovery). */
  newDomainPub: Uint8Array;

  /** Old provider's domain signing private key. */
  oldDomainPriv: Uint8Array;
  oldDomainKeyId: string;

  /** Wall-clock; used for migrated_at clock-skew validation. */
  now: Date;

  /** Old identity key's `created` timestamp (for §3.4 lower bound check). */
  oldIdentityCreated?: Date | null;

  /** Optional clock-skew tolerance. Defaults to 5 minutes. */
  clockSkewMs?: number;

  /**
   * Optional forwarding-policy hook. Called BEFORE countersigning.
   * Throw to refuse the submission with a structured reason.
   */
  forwardingPolicy?: (r: MigrationRecord) => Promise<void> | void;

  /** Optional persistence layer. */
  store?: PublicationStore;

  /** Optional lockout registry. */
  lockout?: LockoutRegistry;
}

/**
 * Old-provider side of cooperative migration: verify the 3
 * submitted signatures, apply optional forwarding policy, register
 * the §6 lockout, countersign with `old_domain_priv`, persist via
 * the store, and return the 4-sig record.
 *
 * In unilateral mode this throws — there is no countersignature
 * step in the unilateral flow.
 */
export async function acceptSubmission(
  input: AcceptSubmissionInput,
): Promise<MigrationRecord> {
  const r = input.record;
  if (r.mode !== "cooperative") {
    throw new Error(
      `migration: acceptSubmission only valid for mode=cooperative (got ${JSON.stringify(r.mode)})`,
    );
  }
  validateMigrationRecord(r);

  // Verify the three submitted signatures (the §3.3 chain is not
  // yet complete — the old domain signature has not been added —
  // so verify each prior pass individually rather than calling the
  // full verifyMigrationRecord.)
  const newIdentityPub = base64Decode(r.new_identity_public_key);
  if (!verifyMigrationPass(r, 0, input.oldIdentityPub)) {
    throw new Error("migration: old_identity_signature verification failed");
  }
  if (!verifyMigrationPass(r, 1, newIdentityPub)) {
    throw new Error("migration: new_identity_signature verification failed");
  }
  if (!verifyMigrationPass(r, 2, input.newDomainPub)) {
    throw new Error("migration: new_domain_signature verification failed");
  }

  // §3.3 migrated_at bound.
  checkMigratedAtBound(
    r,
    input.oldIdentityCreated ?? null,
    input.now,
    input.clockSkewMs,
  );

  // Optional forwarding-policy hook.
  if (input.forwardingPolicy !== undefined) {
    await input.forwardingPolicy(r);
  }

  // Register lockout for the duration of the forwarding window.
  if (input.lockout !== undefined && r.forwarding_window_until !== null) {
    const untilMs = Date.parse(r.forwarding_window_until);
    if (!Number.isNaN(untilMs)) {
      const localpart = r.old_address.includes("@")
        ? r.old_address.split("@")[0] ?? r.old_address
        : r.old_address;
      await input.lockout.reserve(localpart, new Date(untilMs), r.record_id);
    }
  }

  signOldDomain(r, input.oldDomainPriv, input.oldDomainKeyId);

  if (input.store !== undefined) {
    await input.store.putRecord(r);
  }
  return r;
}

/**
 * Per-hook signature for {@link applyThirdPartyPolicy}. A hook
 * receives the published record and returns either nothing
 * (success) or throws with a reason string (the third-party
 * verifier rejects).
 */
export type ThirdPartyHook = (record: MigrationRecord) => Promise<void> | void;

/** Group of policy hooks third parties apply when verifying a published record. */
export interface ThirdPartyPolicy {
  /** Verify the four-signature chain. */
  verifyChain?: ThirdPartyHook;
  /** Operator-defined acceptability policy (domain reputation, etc.). */
  acceptability?: ThirdPartyHook;
  /** Cross-check the record against transparency-log inclusion. */
  transparency?: ThirdPartyHook;
}

/**
 * Run every non-nil hook in `policy`. Aggregates errors so the
 * caller sees every reason at once.
 */
export async function applyThirdPartyPolicy(
  record: MigrationRecord,
  policy: ThirdPartyPolicy,
): Promise<void> {
  const errors: string[] = [];
  for (const hook of [policy.verifyChain, policy.acceptability, policy.transparency]) {
    if (hook === undefined) {
      continue;
    }
    try {
      await hook(record);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  if (errors.length > 0) {
    throw new Error(`migration: third-party policy: ${errors.join("; ")}`);
  }
}

// ---------------------------------------------------------------------------
// Helpers (inline ULID minter — same shape as elsewhere)

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function newRecordID(rand?: (n: number) => Uint8Array): string {
  const r = rand ?? defaultRand;
  const bits = new Uint8Array(16);
  const ms = BigInt(Date.now());
  bits[0] = Number((ms >> 40n) & 0xffn);
  bits[1] = Number((ms >> 32n) & 0xffn);
  bits[2] = Number((ms >> 24n) & 0xffn);
  bits[3] = Number((ms >> 16n) & 0xffn);
  bits[4] = Number((ms >> 8n) & 0xffn);
  bits[5] = Number(ms & 0xffn);
  const random = r(10);
  for (let i = 0; i < 10; i++) {
    bits[6 + i] = random[i] ?? 0;
  }
  let u = 0n;
  for (let i = 0; i < 8; i++) {
    u = (u << 8n) | BigInt(bits[i] ?? 0);
  }
  let u2 = 0n;
  for (let i = 8; i < 16; i++) {
    u2 = (u2 << 8n) | BigInt(bits[i] ?? 0);
  }
  const out = new Array<string>(26);
  for (let i = 25; i >= 13; i--) {
    out[i] = ULID_ALPHABET[Number(u2 & 31n)] ?? "0";
    u2 >>= 5n;
  }
  for (let i = 12; i >= 0; i--) {
    out[i] = ULID_ALPHABET[Number(u & 31n)] ?? "0";
    u >>= 5n;
  }
  return out.join("");
}

function defaultRand(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
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
