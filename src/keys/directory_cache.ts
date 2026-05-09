/**
 * Consumer-side device directory cache per KEY.md §10.6.2 / §10.6.3.
 *
 * A consumer that fetches a {@link DeviceDirectory} for `user_id` MUST
 * record the highest `revision` it has accepted. Any later fetch
 * whose `revision` is strictly less than the cached value MUST be
 * treated with the same suspicion as a key-substitution attempt
 * (rollback).
 *
 * @module
 */

import {
  type DeviceDirectory,
  validateDeviceDirectory,
  verifyDeviceDirectory,
} from "./device_records.js";

/**
 * Optional callback invoked on each `delegated` directory entry to
 * confirm the entry's scoped certificate is published and unexpired
 * per §10.6.3 / §10.3.8. May be `undefined`; passing nothing disables
 * the check.
 */
export type CertificateCheck = (certificateId: string) => void;

/** A typed error subclass for rollback detection failures. */
export class DirectoryRollbackError extends Error {
  override readonly name = "DirectoryRollbackError";
  constructor(
    public readonly userId: string,
    public readonly fetchedRevision: number,
    public readonly cachedRevision: number,
  ) {
    super(
      `keys: directory revision ${fetchedRevision} for ${userId} is less than cached revision ${cachedRevision} (rollback suspected per KEY.md §10.6.2)`,
    );
  }
}

/**
 * Per-user highest accepted revision tracker. Concurrent verifiers
 * see each other's updates because every mutation goes through the
 * same Map.
 */
export class DirectoryCache {
  private highest = new Map<string, number>();

  /**
   * Run every §10.6.3 consumer rule against `dir` and, on success,
   * advance the cached revision for `dir.user_id`. Throws on the
   * first violation; returns nothing on success.
   *
   * Steps run in order so the most-fundamental failures surface
   * first:
   *
   *  1. Schema validation (every device_id unique, every entry's
   *     role/certificate_id consistent, revision >= 0).
   *  2. Identity-key signature verification under `userIdentityPub`.
   *  3. Rollback check against the cached highest revision.
   *  4. Optional certificate-presence callback per delegated entry.
   *
   * @param dir - directory to verify
   * @param userIdentityPub - account's currently active identity public key
   * @param certCheck - per-delegated-entry certificate presence check; optional
   */
  verifyAndCache(
    dir: DeviceDirectory,
    userIdentityPub: Uint8Array,
    certCheck?: CertificateCheck,
  ): void {
    if (dir === undefined || dir === null) {
      throw new Error("keys: directory cache verify nil directory");
    }
    validateDeviceDirectory(dir);
    if (userIdentityPub.length === 0) {
      throw new Error(
        "keys: directory cache verify missing identity public key",
      );
    }
    if (!verifyDeviceDirectory(dir, userIdentityPub)) {
      throw new Error("keys: device directory signature did not verify");
    }
    const cached = this.highest.get(dir.user_id);
    if (cached !== undefined && dir.revision < cached) {
      throw new DirectoryRollbackError(dir.user_id, dir.revision, cached);
    }
    if (certCheck !== undefined) {
      for (const entry of dir.devices) {
        if (entry.role !== "delegated") {
          continue;
        }
        if (entry.certificate_id === null) {
          continue;
        }
        try {
          certCheck(entry.certificate_id);
        } catch (err) {
          throw new Error(
            `keys: directory delegated entry ${entry.device_id}: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }
    this.highest.set(dir.user_id, dir.revision);
  }

  /** Highest accepted revision for `userId`, or 0 if none cached. */
  highestRevision(userId: string): number {
    return this.highest.get(userId) ?? 0;
  }

  /**
   * Forget the cached revision for `userId`. Intended for tests and
   * operator-driven manual overrides; production consumers MUST NOT
   * reset cached revisions absent strong evidence the prior cache
   * was poisoned.
   */
  reset(userId: string): void {
    this.highest.delete(userId);
  }
}
