/**
 * Tests for the new handshake helpers: capabilities + abort.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  ChallengeInvalidError,
  HandshakeRejectedError,
  ImplementedSuites,
  SuitePreferenceOrder,
  buildClientRejection,
  defaultClientCapabilities,
  defaultServerCapabilities,
  isChallengeInvalid,
  isResumptionFailed,
  negotiateCapabilities,
} from "./index.js";

describe("negotiateCapabilities", () => {
  test("picks pq-kyber768-x25519 when both sides support it", () => {
    const out = negotiateCapabilities(
      {
        encryption_algorithms: [
          "pq-kyber768-x25519",
          "x25519-chacha20-poly1305",
        ],
        extensions: [],
      },
      {
        encryption_algorithms: [
          "pq-kyber768-x25519",
          "x25519-chacha20-poly1305",
        ],
        extensions: [],
      },
    );
    expect(out.encryption_algorithm).toBe("pq-kyber768-x25519");
  });

  test("falls back to baseline when only baseline is mutual", () => {
    const out = negotiateCapabilities(
      {
        encryption_algorithms: ["pq-kyber768-x25519", "x25519-chacha20-poly1305"],
        extensions: [],
      },
      {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
    );
    expect(out.encryption_algorithm).toBe("x25519-chacha20-poly1305");
  });

  test("throws on no mutually supported suite", () => {
    expect(() =>
      negotiateCapabilities(
        { encryption_algorithms: ["future-suite"], extensions: [] },
        { encryption_algorithms: ["x25519-chacha20-poly1305"], extensions: [] },
      ),
    ).toThrow(/no mutually supported/);
  });

  test("intersects extensions, ordered by offered", () => {
    const out = negotiateCapabilities(
      {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: ["a", "b", "c"],
      },
      {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: ["c", "b"],
      },
    );
    expect(out.extensions).toEqual(["b", "c"]);
  });

  test("max_envelope_size: smaller of two when both advertise", () => {
    const out = negotiateCapabilities(
      {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
        max_envelope_size: 1_000_000,
      } as never,
      {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
        max_envelope_size: 500_000,
      } as never,
    );
    expect(out.max_envelope_size).toBe(500_000);
  });

  test("default capabilities advertise both suites", () => {
    expect(defaultClientCapabilities().encryption_algorithms).toContain(
      "pq-kyber768-x25519",
    );
    expect(defaultServerCapabilities().encryption_algorithms).toContain(
      "x25519-chacha20-poly1305",
    );
  });

  test("preference order is PQ first, baseline second", () => {
    expect(SuitePreferenceOrder[0]).toBe("pq-kyber768-x25519");
    expect(SuitePreferenceOrder[1]).toBe("x25519-chacha20-poly1305");
    expect(ImplementedSuites.length).toBeGreaterThan(0);
  });
});

describe("ChallengeInvalidError + isChallengeInvalid", () => {
  test("error message includes detail", () => {
    const e = new ChallengeInvalidError("prefix too short");
    expect(e.message).toBe("handshake: challenge_invalid: prefix too short");
    expect(e.detail).toBe("prefix too short");
  });

  test("isChallengeInvalid recognizes the type", () => {
    expect(isChallengeInvalid(new ChallengeInvalidError("x"))).toBe(true);
    expect(isChallengeInvalid(new Error("plain"))).toBe(false);
    expect(isChallengeInvalid(null)).toBe(false);
  });
});

describe("buildClientRejection", () => {
  test("emits canonical bytes with party=client", () => {
    const bytes = buildClientRejection("challenge_invalid", "prefix mismatch");
    const decoded = JSON.parse(new TextDecoder().decode(bytes));
    expect(decoded.party).toBe("client");
    expect(decoded.step).toBe("rejected");
    expect(decoded.type).toBe("SEMP_HANDSHAKE");
    expect(decoded.reason_code).toBe("challenge_invalid");
    expect(decoded.reason).toBe("prefix mismatch");
    // No server_signature on a client-side rejection.
    expect("server_signature" in decoded).toBe(false);
  });

  test("rejects empty reason_code", () => {
    expect(() => buildClientRejection("")).toThrow(/empty reason_code/);
  });

  test("optional reason defaults to empty string", () => {
    const bytes = buildClientRejection("challenge_invalid");
    const decoded = JSON.parse(new TextDecoder().decode(bytes));
    expect(decoded.reason).toBe("");
  });
});

describe("isResumptionFailed", () => {
  test("recognizes resumption_failed / session_expired / no_session", () => {
    for (const code of ["resumption_failed", "session_expired", "no_session"]) {
      expect(
        isResumptionFailed(new HandshakeRejectedError("sid", code, "x")),
      ).toBe(true);
    }
  });

  test("rejects other reason codes", () => {
    for (const code of ["auth_failed", "policy_forbidden", "blocked"]) {
      expect(
        isResumptionFailed(new HandshakeRejectedError("sid", code, "x")),
      ).toBe(false);
    }
  });

  test("rejects non-HandshakeRejectedError values", () => {
    expect(isResumptionFailed(new Error("plain"))).toBe(false);
    expect(isResumptionFailed(null)).toBe(false);
  });
});
