/**
 * Device-records tests. Cover registration (inner authorization +
 * outer identity signature), revocation, directory, and key
 * revocation publication.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { fingerprint, publicKeyFromSeed } from "./sign.js";
import {
  type DeviceDirectory,
  type DeviceRegistration,
  type DeviceRevocation,
  findDevice,
  requiresIdentityRotation,
  signDeviceAuthorization,
  signDeviceDirectory,
  signDeviceRegistration,
  signDeviceRevocation,
  verifyDeviceAuthorization,
  verifyDeviceDirectory,
  verifyDeviceRegistration,
  verifyDeviceRevocation,
} from "./device_records.js";
import {
  type RevocationPublication,
  isReversibleReason,
  signRevocationPublication,
  verifyRevocationPublication,
} from "./key_revocation.js";

function deterministicSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function emptyRegistration(): DeviceRegistration {
  return {
    type: "SEMP_DEVICE",
    step: "register",
    version: "1.0.0",
    user_id: "alice@example.com",
    device_id: "01JNEW00000000000000000000",
    device_name: "Alice's Laptop",
    device_type: "computer",
    device_public_key: "AAAA",
    device_identity_pubkey_algorithm: "ed25519",
    enrolled_at: "2026-04-21T10:00:00Z",
    role: "full_access",
    certificate_id: null,
    authorization: {
      method: "qr_scan",
      authorizing_device_id: "01JOLD00000000000000000000",
      authorizing_signature: { algorithm: "", key_id: "", value: "" },
    },
    signature: { algorithm: "", key_id: "", value: "" },
  };
}

describe("DeviceRegistration: inner authorization + outer identity signatures", () => {
  test("authorization round-trip", () => {
    const authSeed = deterministicSeed(0xa1);
    const authPub = publicKeyFromSeed(authSeed);
    const reg = emptyRegistration();
    const enrollNonce = new Uint8Array(32).fill(0x77);
    signDeviceAuthorization({
      registration: reg,
      authorizingDeviceSeed: authSeed,
      authorizingDeviceId: "01JOLD00000000000000000000",
      authorizingDeviceKeyId: fingerprint(authPub),
      enrollNonce,
      method: "qr_scan",
    });
    expect(reg.authorization.method).toBe("qr_scan");
    expect(reg.authorization.authorizing_signature.value).not.toBe("");
    expect(verifyDeviceAuthorization(reg, authPub, enrollNonce)).toBe(true);
  });

  test("authorization fails verification under different enrollNonce", () => {
    const authSeed = deterministicSeed(0xa1);
    const authPub = publicKeyFromSeed(authSeed);
    const reg = emptyRegistration();
    signDeviceAuthorization({
      registration: reg,
      authorizingDeviceSeed: authSeed,
      authorizingDeviceId: "01JOLD00000000000000000000",
      authorizingDeviceKeyId: fingerprint(authPub),
      enrollNonce: new Uint8Array(32).fill(0x77),
      method: "qr_scan",
    });
    const wrongNonce = new Uint8Array(32).fill(0x88);
    expect(verifyDeviceAuthorization(reg, authPub, wrongNonce)).toBe(false);
  });

  test("outer identity signature round-trip", () => {
    const authSeed = deterministicSeed(0xa1);
    const authPub = publicKeyFromSeed(authSeed);
    const idSeed = deterministicSeed(0xb1);
    const idPub = publicKeyFromSeed(idSeed);

    const reg = emptyRegistration();
    signDeviceAuthorization({
      registration: reg,
      authorizingDeviceSeed: authSeed,
      authorizingDeviceId: "01JOLD00000000000000000000",
      authorizingDeviceKeyId: fingerprint(authPub),
      enrollNonce: new Uint8Array(32).fill(0x77),
      method: "qr_scan",
    });
    signDeviceRegistration(reg, idSeed, fingerprint(idPub));
    expect(verifyDeviceRegistration(reg, idPub)).toBe(true);
  });

  test("delegated role rejects null certificate_id", () => {
    const reg = emptyRegistration();
    reg.role = "delegated";
    reg.certificate_id = null;
    reg.authorization.authorizing_signature.value = "AAA=";
    expect(() => signDeviceRegistration(reg, deterministicSeed(1), "x")).toThrow(
      /certificate_id/,
    );
  });

  test("full_access role rejects non-null certificate_id", () => {
    const reg = emptyRegistration();
    reg.certificate_id = "some-cert-id";
    reg.authorization.authorizing_signature.value = "AAA=";
    expect(() => signDeviceRegistration(reg, deterministicSeed(1), "x")).toThrow(
      /certificate_id/,
    );
  });
});

describe("DeviceRevocation", () => {
  function emptyRevocation(): DeviceRevocation {
    return {
      type: "SEMP_DEVICE_REVOCATION",
      version: "1.0.0",
      user_id: "alice@example.com",
      device_id: "01JOLD00000000000000000000",
      reason: "lost",
      revoked_at: "2026-04-22T10:00:00Z",
      revoked_by_device_id: "01JNEW00000000000000000000",
      replacement_device_id: null,
      signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0xc1);
    const pub = publicKeyFromSeed(seed);
    const rev = emptyRevocation();
    signDeviceRevocation(rev, seed, fingerprint(pub));
    expect(verifyDeviceRevocation(rev, pub)).toBe(true);
  });

  test("superseded requires replacement_device_id", () => {
    const rev = emptyRevocation();
    rev.reason = "superseded";
    expect(() => signDeviceRevocation(rev, deterministicSeed(1), "x")).toThrow(
      /replacement_device_id/,
    );
    rev.replacement_device_id = "01JREPLACEMENT0000000000000";
    signDeviceRevocation(rev, deterministicSeed(1), "x");
  });

  test("non-superseded reasons reject replacement_device_id", () => {
    const rev = emptyRevocation();
    rev.replacement_device_id = "01JREPLACE0000000000000";
    expect(() => signDeviceRevocation(rev, deterministicSeed(1), "x")).toThrow(
      /replacement_device_id/,
    );
  });

  test("requiresIdentityRotation matches §10.5.5", () => {
    expect(requiresIdentityRotation("key_compromise")).toBe(true);
    expect(requiresIdentityRotation("lost")).toBe(false);
    expect(requiresIdentityRotation("retired")).toBe(false);
    expect(requiresIdentityRotation("superseded")).toBe(false);
  });
});

describe("DeviceDirectory", () => {
  function emptyDirectory(): DeviceDirectory {
    return {
      type: "SEMP_DEVICE_DIRECTORY",
      version: "1.0.0",
      user_id: "alice@example.com",
      revision: 1,
      issued_at: "2026-04-21T10:00:00Z",
      devices: [
        {
          device_id: "01JNEW00000000000000000000",
          device_public_key: "AAAA",
          device_identity_pubkey_algorithm: "ed25519",
          role: "full_access",
          certificate_id: null,
          enrolled_at: "2026-04-21T10:00:00Z",
          device_name: "Alice's Laptop",
          device_type: "computer",
        },
      ],
      signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0xd1);
    const pub = publicKeyFromSeed(seed);
    const dir = emptyDirectory();
    signDeviceDirectory(dir, seed, fingerprint(pub));
    expect(verifyDeviceDirectory(dir, pub)).toBe(true);
  });

  test("rejects duplicate device_id", () => {
    const dir = emptyDirectory();
    dir.devices.push({ ...dir.devices[0]! });
    expect(() => signDeviceDirectory(dir, deterministicSeed(1), "x")).toThrow(
      /more than once/,
    );
  });

  test("findDevice locates and misses cleanly", () => {
    const dir = emptyDirectory();
    expect(findDevice(dir, "01JNEW00000000000000000000")).not.toBeNull();
    expect(findDevice(dir, "missing")).toBeNull();
  });

  test("rejects negative revision", () => {
    const dir = emptyDirectory();
    dir.revision = -1;
    expect(() => signDeviceDirectory(dir, deterministicSeed(1), "x")).toThrow(
      /revision/,
    );
  });
});

describe("RevocationPublication", () => {
  function emptyRevocationPub(): RevocationPublication {
    return {
      type: "SEMP_KEY_REVOCATION",
      version: "1.0.0",
      revoked_keys: [
        {
          key_id: "0".repeat(64),
          reason: "key_compromise",
          revoked_at: "2026-04-22T00:00:00Z",
        },
      ],
      signature: { algorithm: "", key_id: "", value: "" },
    };
  }

  test("round-trip", () => {
    const seed = deterministicSeed(0xe1);
    const pub = publicKeyFromSeed(seed);
    const r = emptyRevocationPub();
    signRevocationPublication(r, seed, fingerprint(pub));
    expect(verifyRevocationPublication(r, pub)).toBe(true);
  });

  test("isReversibleReason", () => {
    expect(isReversibleReason("temporary_hold")).toBe(true);
    expect(isReversibleReason("key_compromise")).toBe(false);
    expect(isReversibleReason("superseded")).toBe(false);
    expect(isReversibleReason("cessation_of_operation")).toBe(false);
  });

  test("rejects unknown reason", () => {
    const r = emptyRevocationPub();
    (r.revoked_keys[0] as unknown as { reason: string }).reason = "bogus";
    expect(() => signRevocationPublication(r, deterministicSeed(1), "x")).toThrow(
      /reason/,
    );
  });
});
