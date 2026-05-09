/**
 * Tests for {@link partitionStages} per DELIVERY.md §3.2.1.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import type {
  DeviceCertificate,
  Scope,
} from "../keys/index.js";
import type { DeviceDirectory } from "../keys/index.js";

import { partitionStages } from "./stage_partition.js";

function fullAccess(deviceId: string, pub: string): DeviceDirectory["devices"][number] {
  return {
    device_id: deviceId,
    device_public_key: pub,
    device_identity_pubkey_algorithm: "ed25519",
    role: "full_access",
    certificate_id: null,
    enrolled_at: "2026-05-08T10:00:00Z",
    device_name: "FA",
    device_type: "computer",
  };
}

function delegated(deviceId: string, pub: string, certId: string): DeviceDirectory["devices"][number] {
  return {
    device_id: deviceId,
    device_public_key: pub,
    device_identity_pubkey_algorithm: "ed25519",
    role: "delegated",
    certificate_id: certId,
    enrolled_at: "2026-05-08T10:00:00Z",
    device_name: "DEL",
    device_type: "computer",
  };
}

function makeCert(scope: Scope): DeviceCertificate {
  return {
    type: "SEMP_DEVICE_CERTIFICATE",
    version: "1.0.0",
    device_id: "DEL",
    device_public_key: "AAAA",
    account: "alice@example.com",
    issued_by: "FA",
    issued_at: "2026-05-08T10:00:00Z",
    expires_at: "2026-05-08T20:00:00Z",
    scope,
    signature: { algorithm: "ed25519", key_id: "issuer-fp", value: "" },
  };
}

const emptyResource = { read: false, write: false, rate_limits: [] };

function unrestrictedReceiveAtStage(stage: number): Scope {
  return {
    send: { mode: "unrestricted", rate_limits: [] },
    receive: {
      mode: "unrestricted",
      rate_limits: [],
      delivery_stage: stage,
    },
    blocklist: emptyResource,
    keys: emptyResource,
    devices: emptyResource,
  };
}

function makeDirectory(
  devices: DeviceDirectory["devices"],
): DeviceDirectory {
  return {
    type: "SEMP_DEVICE_DIRECTORY",
    version: "1.0.0",
    user_id: "alice@example.com",
    revision: 1,
    issued_at: "2026-05-08T10:00:00Z",
    devices,
    signature: { algorithm: "ed25519", key_id: "alice-id", value: "sig" },
  };
}

describe("partitionStages", () => {
  test("only enclosure-recipients are eligible", () => {
    const dir = makeDirectory([
      fullAccess("FA1", "PUB-FA1"),
      fullAccess("FA2", "PUB-FA2"),
    ]);
    // Only FA1 has an enclosure-recipient wrap.
    const stages = partitionStages({
      directory: dir,
      certificateProvider: () => null,
      enclosureRecipients: new Set(["PUB-FA1"]),
      senderAddress: { address: "bob@example.com" },
    });
    expect(stages).toHaveLength(1);
    expect(stages[0]!.pending_device_ids).toEqual(["FA1"]);
    expect(stages[0]!.stage).toBe(1); // no delegate; full-access at stage 1
  });

  test("delegate at stage 1 forces full-access to stage 2", () => {
    const dir = makeDirectory([
      fullAccess("FA1", "PUB-FA1"),
      delegated("DEL1", "PUB-DEL1", "cert-1"),
    ]);
    const cert = makeCert(unrestrictedReceiveAtStage(1));
    const stages = partitionStages({
      directory: dir,
      certificateProvider: (id) => (id === "DEL1" ? cert : null),
      enclosureRecipients: new Set(["PUB-FA1", "PUB-DEL1"]),
      senderAddress: { address: "bob@example.com" },
    });
    expect(stages.map((s) => s.stage)).toEqual([1, 2]);
    expect(stages[0]!.pending_device_ids).toEqual(["DEL1"]);
    expect(stages[1]!.pending_device_ids).toEqual(["FA1"]);
  });

  test("delegate with mode=none excludes the device but does NOT bump full-access", () => {
    const dir = makeDirectory([
      fullAccess("FA1", "PUB-FA1"),
      delegated("DEL1", "PUB-DEL1", "cert-1"),
    ]);
    const noneCert = makeCert({
      send: { mode: "none", rate_limits: [] },
      receive: { mode: "none", rate_limits: [], delivery_stage: 1 },
      blocklist: emptyResource,
      keys: emptyResource,
      devices: emptyResource,
    });
    const stages = partitionStages({
      directory: dir,
      certificateProvider: () => noneCert,
      enclosureRecipients: new Set(["PUB-FA1", "PUB-DEL1"]),
      senderAddress: { address: "bob@example.com" },
    });
    expect(stages).toHaveLength(1);
    expect(stages[0]!.stage).toBe(1);
    expect(stages[0]!.pending_device_ids).toEqual(["FA1"]);
  });

  test("delegate without current cert is excluded", () => {
    const dir = makeDirectory([
      fullAccess("FA1", "PUB-FA1"),
      delegated("DEL1", "PUB-DEL1", "cert-1"),
    ]);
    const stages = partitionStages({
      directory: dir,
      certificateProvider: () => null,
      enclosureRecipients: new Set(["PUB-FA1", "PUB-DEL1"]),
      senderAddress: { address: "bob@example.com" },
    });
    expect(stages).toHaveLength(1);
    expect(stages[0]!.pending_device_ids).toEqual(["FA1"]);
  });

  test("max_stage tally counts delegates with mode!=none even when sender rejected", () => {
    // Delegate's allow list rejects bob@example.com, but its mode is
    // unrestricted-with-allow == restricted; so the sender DOES match
    // when allowed. Use restricted with empty allow → no match.
    const dir = makeDirectory([
      fullAccess("FA1", "PUB-FA1"),
      delegated("DEL1", "PUB-DEL1", "cert-1"),
    ]);
    const restrictedCert = makeCert({
      send: { mode: "unrestricted", rate_limits: [] },
      receive: {
        mode: "restricted",
        allow: [{ type: "user", address: "alice@example.com" }],
        rate_limits: [],
        delivery_stage: 1,
      },
      blocklist: emptyResource,
      keys: emptyResource,
      devices: emptyResource,
    });
    const stages = partitionStages({
      directory: dir,
      certificateProvider: () => restrictedCert,
      enclosureRecipients: new Set(["PUB-FA1", "PUB-DEL1"]),
      senderAddress: { address: "bob@example.com" },
    });
    // DEL1 is excluded (doesn't match allow), but its mode!=none
    // contributes to maxDelegateMode. Full access goes to stage 2.
    expect(stages).toHaveLength(1);
    expect(stages[0]!.stage).toBe(2);
    expect(stages[0]!.pending_device_ids).toEqual(["FA1"]);
  });

  test("returns empty when no devices are eligible", () => {
    const dir = makeDirectory([fullAccess("FA1", "PUB-FA1")]);
    const stages = partitionStages({
      directory: dir,
      certificateProvider: () => null,
      enclosureRecipients: new Set(), // no enclosure recipients
      senderAddress: { address: "bob@example.com" },
    });
    expect(stages).toHaveLength(0);
  });

  test("groups multiple delegates into the same stage", () => {
    const dir = makeDirectory([
      delegated("DEL1", "PUB-DEL1", "c1"),
      delegated("DEL2", "PUB-DEL2", "c2"),
    ]);
    const cert = makeCert(unrestrictedReceiveAtStage(1));
    const stages = partitionStages({
      directory: dir,
      certificateProvider: () => cert,
      enclosureRecipients: new Set(["PUB-DEL1", "PUB-DEL2"]),
      senderAddress: { address: "bob@example.com" },
    });
    expect(stages).toHaveLength(1);
    expect(stages[0]!.pending_device_ids).toEqual(["DEL1", "DEL2"]);
  });
});
