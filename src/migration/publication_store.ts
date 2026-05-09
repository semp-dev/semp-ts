/**
 * Persistence interface for published migration records per
 * MIGRATION.md §3.4 + §6.2.
 *
 * Even after the local-part is reassigned, the published migration
 * record stays accessible as historical evidence. The store keys
 * records by both `old_address` (for sender-side address lookups
 * after a delivery failure) and by `record_id` (for direct fetches
 * via `record_url`).
 *
 * @module
 */

import type { MigrationRecord } from "./types.js";

/** Persistence interface for migration records. */
export interface PublicationStore {
  /** Persist `r`. Idempotent on repeated calls with the same record_id. */
  putRecord(r: MigrationRecord): Promise<void>;

  /**
   * Return the most recent published record for `oldAddress`, or
   * null if none exists.
   */
  getByOldAddress(oldAddress: string): Promise<MigrationRecord | null>;

  /** Return the record with `recordId`, or null if not found. */
  getByRecordId(recordId: string): Promise<MigrationRecord | null>;
}

/** Reference {@link PublicationStore}. Single-process only. */
export class InMemoryPublicationStore implements PublicationStore {
  private readonly byRecordId = new Map<string, MigrationRecord>();
  private readonly byOldAddress = new Map<string, MigrationRecord>();

  async putRecord(r: MigrationRecord): Promise<void> {
    if (r.record_id === "") {
      throw new Error("migration: empty record_id");
    }
    if (r.old_address === "") {
      throw new Error("migration: empty old_address");
    }
    const cp: MigrationRecord = JSON.parse(JSON.stringify(r));
    this.byRecordId.set(r.record_id, cp);
    // The most recent record for an address wins (later put overrides).
    this.byOldAddress.set(r.old_address.toLowerCase(), cp);
  }

  async getByOldAddress(oldAddress: string): Promise<MigrationRecord | null> {
    const r = this.byOldAddress.get(oldAddress.toLowerCase());
    if (r === undefined) {
      return null;
    }
    return JSON.parse(JSON.stringify(r)) as MigrationRecord;
  }

  async getByRecordId(recordId: string): Promise<MigrationRecord | null> {
    const r = this.byRecordId.get(recordId);
    if (r === undefined) {
      return null;
    }
    return JSON.parse(JSON.stringify(r)) as MigrationRecord;
  }
}
