/**
 * Manifest-contributors cross-check per RECOVERY.md §5.2.
 *
 * Before trusting a fetched recovery-set manifest, a verifier MUST
 * confirm that each contributor's `device_identity_pubkey` matches
 * the user's currently-published device directory. The
 * {@link DirectoryView} interface lets recovery code consult the
 * device directory without depending on the keys package.
 *
 * @module
 */

import type { RecoverySetManifest } from "./types.js";

/**
 * Minimal device-directory read surface needed by the cross-check.
 * The concrete `DeviceDirectory` type in `keys/` exposes a
 * `findDevice` helper that satisfies this shape.
 */
export interface DirectoryView {
  /** The user this directory belongs to. */
  userId(): string;
  /**
   * Look up `deviceId`. Returns `(algorithm, public_key, true)`
   * when present; `("", "", false)` when absent.
   */
  findDevice(deviceId: string): {
    algorithm: string;
    publicKey: string;
    found: boolean;
  };
}

/** Why a contributor cross-check failed. */
export type CrossCheckReason =
  | "user_mismatch"
  | "device_missing"
  | "pubkey_mismatch"
  | "algorithm_mismatch";

/**
 * Error thrown by {@link crossCheckManifestContributors} when a
 * contributor entry does not match the device directory.
 */
export class ManifestCrossCheckError extends Error {
  override readonly name = "ManifestCrossCheckError";
  readonly reason: CrossCheckReason;
  /** Contributor share index (1-based) that caused the failure. */
  readonly shareIndex: number;
  /** Contributor device id that caused the failure. */
  readonly deviceId: string;

  constructor(
    reason: CrossCheckReason,
    shareIndex: number,
    deviceId: string,
    detail: string,
  ) {
    super(`recovery: ${detail}`);
    this.reason = reason;
    this.shareIndex = shareIndex;
    this.deviceId = deviceId;
  }
}

/**
 * Cross-check that every contributor in `m` corresponds to a
 * device in `directory` per §5.2:
 *
 *  - Manifest user_id MUST match directory.userId.
 *  - Each contributor's device_id MUST be present in the directory.
 *  - The directory entry's public_key + algorithm MUST match the
 *    manifest contributor's device_identity_pubkey.
 *
 * Throws {@link ManifestCrossCheckError} on the first violation;
 * returns silently when every contributor matches.
 */
export function crossCheckManifestContributors(
  m: RecoverySetManifest,
  directory: DirectoryView,
  manifestUserId: string,
): void {
  if (directory.userId() !== manifestUserId) {
    throw new ManifestCrossCheckError(
      "user_mismatch",
      0,
      "",
      `manifest user ${JSON.stringify(manifestUserId)} does not match directory user ${JSON.stringify(directory.userId())}`,
    );
  }
  for (const c of m.contributors) {
    const lookup = directory.findDevice(c.device_id);
    if (!lookup.found) {
      throw new ManifestCrossCheckError(
        "device_missing",
        c.share_index,
        c.device_id,
        `manifest contributor share_index=${c.share_index} device_id=${JSON.stringify(c.device_id)} is not in the directory`,
      );
    }
    if (lookup.algorithm !== c.device_identity_pubkey.algorithm) {
      throw new ManifestCrossCheckError(
        "algorithm_mismatch",
        c.share_index,
        c.device_id,
        `manifest contributor share_index=${c.share_index} algorithm ${JSON.stringify(c.device_identity_pubkey.algorithm)} does not match directory ${JSON.stringify(lookup.algorithm)}`,
      );
    }
    if (lookup.publicKey !== c.device_identity_pubkey.public_key) {
      throw new ManifestCrossCheckError(
        "pubkey_mismatch",
        c.share_index,
        c.device_id,
        `manifest contributor share_index=${c.share_index} public_key does not match directory entry`,
      );
    }
  }
}
