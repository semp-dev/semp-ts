/**
 * Migration notice messages per MIGRATION.md §4.
 *
 * A `SEMP_MIGRATION_NOTICE` is what a server returns to a sender
 * that attempted to deliver to a migrated address. It carries a
 * pointer to the published migration record (URL + record_id) so
 * the sender's stack can fetch and verify it before redirecting.
 *
 * @module
 */

import {
  type MigrationNotice,
  type MigrationNoticeRejection,
  type MigrationRecord,
  MigrationNoticeType,
  MigrationRecordVersion,
} from "./types.js";

/** Inputs to {@link buildMigrationNotice}. */
export interface BuildMigrationNoticeInput {
  record: MigrationRecord;
  /** URL pattern with `{record_id}` placeholder, e.g. `https://old.example/migration/{record_id}`. */
  recordUrlPattern: string;
  /** Optional pre-assigned notice id; auto-generated when omitted. */
  noticeId?: string;
  /** Wall-clock; defaults to `() => new Date()`. */
  nowFn?: () => Date;
  /** Random source for ULID generation. */
  rand?: (n: number) => Uint8Array;
}

/**
 * Build a {@link MigrationNotice} that points at the published
 * `record`. The notice is unsigned — the recipient sender verifies
 * the underlying record by fetching `record_url` and running
 * `verifyMigrationRecord`.
 */
export function buildMigrationNotice(
  input: BuildMigrationNoticeInput,
): MigrationNotice {
  if (input.recordUrlPattern === "" || !input.recordUrlPattern.includes("{record_id}")) {
    throw new Error(
      "migration: recordUrlPattern must include {record_id} placeholder",
    );
  }
  const recordUrl = input.recordUrlPattern.replace(
    "{record_id}",
    encodeURIComponent(input.record.record_id),
  );
  const noticeId = input.noticeId ?? newULID(input.rand);
  const nowFn = input.nowFn ?? (() => new Date());
  return {
    type: MigrationNoticeType,
    version: MigrationRecordVersion,
    notice_id: noticeId,
    record_id: input.record.record_id,
    record_url: recordUrl,
    old_address: input.record.old_address,
    new_address: input.record.new_address,
    mode: input.record.mode,
    issued_at: isoSecond(nowFn()),
  };
}

/** Construct a rejection wrapper to refuse honoring a notice. */
export function newMigrationNoticeRejection(
  notice: MigrationNotice,
  reason: string,
): MigrationNoticeRejection {
  return { notice, reason };
}

// ---------------------------------------------------------------------------
// Helpers (inlined ULID minter — same as elsewhere in the codebase)

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function newULID(rand?: (n: number) => Uint8Array): string {
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

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
