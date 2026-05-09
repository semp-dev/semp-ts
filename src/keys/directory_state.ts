/**
 * Server-side per-user device directory state per KEY.md §10.6.
 *
 * A home server keeps a {@link DirectoryState} per account. Every
 * enrollment (§10.1) or revocation (§10.5) bumps `revision` and
 * produces a fresh signed {@link DeviceDirectory} record consumers
 * fetch via the directory endpoint.
 *
 * @module
 */

import {
  type DeviceDirectory,
  type DeviceDirectoryEntry,
  DeviceDirectoryType,
  DeviceRecordVersion,
  signDeviceDirectory,
} from "./device_records.js";

/** Inputs to {@link DirectoryState}. */
export interface DirectoryStateConfig {
  userId: string;
  /** 32-byte Ed25519 seed for the user's identity key. */
  identitySeed: Uint8Array;
  identityKeyId: string;
  /**
   * Initial seed of devices, typically loaded from durable storage at
   * startup. The constructor sorts them by `device_id` and emits
   * revision 1. Pass `[]` to start empty (revision 0; first add bumps
   * to 1).
   */
  initial?: DeviceDirectoryEntry[];
  /** Wall-clock used to stamp `issued_at`. Defaults to `() => new Date()`. */
  now?: () => Date;
}

/**
 * Per-user directory state: tracks the active device set, increments
 * a monotonic revision counter, and emits a freshly signed
 * {@link DeviceDirectory} on every change.
 */
export class DirectoryState {
  private readonly userId: string;
  private readonly identitySeed: Uint8Array;
  private readonly identityKeyId: string;
  private readonly nowFn: () => Date;
  private readonly devices = new Map<string, DeviceDirectoryEntry>();
  private revisionCounter = 0;
  private currentDir: DeviceDirectory | null = null;

  constructor(cfg: DirectoryStateConfig) {
    if (cfg.userId === "") {
      throw new Error("keys: directory state missing user_id");
    }
    if (cfg.identitySeed.length === 0 || cfg.identityKeyId === "") {
      throw new Error("keys: directory state missing identity key");
    }
    this.userId = cfg.userId;
    this.identitySeed = cfg.identitySeed;
    this.identityKeyId = cfg.identityKeyId;
    this.nowFn = cfg.now ?? (() => new Date());
    if (cfg.initial !== undefined) {
      for (const d of cfg.initial) {
        if (d.device_id === "") {
          throw new Error(
            "keys: directory initial seed entry missing device_id",
          );
        }
        if (this.devices.has(d.device_id)) {
          throw new Error(
            `keys: directory initial seed has duplicate device_id ${JSON.stringify(d.device_id)}`,
          );
        }
        this.devices.set(d.device_id, d);
      }
      if (this.devices.size > 0) {
        this.emit();
      }
    }
  }

  /**
   * Record an enrollment per §10.1 and emit a new directory revision.
   * Throws when `device_id` is empty or already present.
   */
  addDevice(entry: DeviceDirectoryEntry): DeviceDirectory {
    if (entry.device_id === "") {
      throw new Error("keys: directory entry missing device_id");
    }
    if (entry.device_public_key === "") {
      throw new Error("keys: directory entry missing device_public_key");
    }
    if (entry.role === "full_access" && entry.certificate_id !== null) {
      throw new Error(
        "keys: directory entry full_access MUST have certificate_id = null",
      );
    }
    if (entry.role === "delegated") {
      if (entry.certificate_id === null || entry.certificate_id === "") {
        throw new Error(
          "keys: directory entry delegated MUST set certificate_id",
        );
      }
    }
    if (this.devices.has(entry.device_id)) {
      throw new Error(
        `keys: directory already contains device_id ${JSON.stringify(entry.device_id)}`,
      );
    }
    this.devices.set(entry.device_id, entry);
    this.emit();
    return this.currentDir!;
  }

  /**
   * Record a revocation per §10.5 by removing `deviceId` from the
   * active set and emitting a new directory revision. Returns
   * `{ directory, removed }` where `removed === false` means the
   * device wasn't in the directory and the directory is unchanged
   * (no new revision was emitted).
   */
  revokeDevice(deviceId: string): {
    directory: DeviceDirectory | null;
    removed: boolean;
  } {
    if (deviceId === "") {
      throw new Error("keys: directory revoke missing device_id");
    }
    if (!this.devices.has(deviceId)) {
      return { directory: this.currentDir, removed: false };
    }
    this.devices.delete(deviceId);
    this.emit();
    return { directory: this.currentDir, removed: true };
  }

  /**
   * Most recently emitted directory, or `null` when the state has
   * never emitted (empty initial set and no `addDevice` calls). The
   * returned object is the live record; callers MUST NOT mutate it.
   */
  current(): DeviceDirectory | null {
    return this.currentDir;
  }

  /** Current monotonic revision counter. */
  revision(): number {
    return this.revisionCounter;
  }

  private emit(): void {
    this.revisionCounter += 1;
    const entries = Array.from(this.devices.values()).sort((a, b) =>
      a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0,
    );
    const dir: DeviceDirectory = {
      type: DeviceDirectoryType,
      version: DeviceRecordVersion,
      user_id: this.userId,
      revision: this.revisionCounter,
      issued_at: isoSecond(this.nowFn()),
      devices: entries,
      signature: { algorithm: "", key_id: "", value: "" },
    };
    try {
      signDeviceDirectory(dir, this.identitySeed, this.identityKeyId);
    } catch (err) {
      // Roll back the revision bump so the next attempt does not skip
      // a number.
      this.revisionCounter -= 1;
      throw new Error(
        `keys: sign device directory: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    this.currentDir = dir;
  }
}

/**
 * Multi-user wrapper a home server keeps: one {@link DirectoryState}
 * per account it hosts. Lookups are by `user_id`.
 */
export class DirectoryStore {
  private states = new Map<string, DirectoryState>();

  /** Associate a fresh state with `userId`. Throws when `userId` is already present. */
  register(userId: string, state: DirectoryState): void {
    if (userId === "") {
      throw new Error("keys: directory store register missing user_id");
    }
    if (this.states.has(userId)) {
      throw new Error(
        `keys: directory store already has user ${JSON.stringify(userId)}`,
      );
    }
    this.states.set(userId, state);
  }

  /** Return the state for `userId`, or `null` when not registered. */
  lookup(userId: string): DirectoryState | null {
    return this.states.get(userId) ?? null;
  }
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
