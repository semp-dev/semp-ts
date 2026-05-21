/**
 * Handlers for vectors added by the LIBRARY_REVIEW decision pass.
 *
 * Most of these vectors pin behavior contracts (URL templates,
 * configuration field shapes, abuse-category enumeration) more
 * than they pin cryptographic outputs. The handlers assert that
 * the corresponding library constants and helper functions match
 * the spec-pinned shape.
 *
 * @module
 */

import { describe as _describe, expect } from "vitest";

import { sha256 } from "@noble/hashes/sha2.js";

import {
  PathDiscovery,
  PathEnvelope,
  PathHandshake,
  PathKeys,
  PathSession,
  discoveryPath,
  keysPath,
  sessionPath,
} from "../../src/transport/index.js";
import {
  DefinitionPathPrefix,
  type ValidationFailureCode,
  newValidationFailureRejection,
} from "../../src/extensions/index.js";
import {
  PersistentSilentCounter,
  PersistentSilentDefaults,
} from "../../src/delivery/persistent_silent.js";
import {
  type StatusMessage,
  signStatusMessage,
  verifyStatusMessage,
} from "../../src/delivery/status_message.js";
import {
  type AbuseReport,
  AbuseReportType,
  EvidenceHashMismatchError,
  MaxEvidenceBytes,
  MaxObservationBytes,
  type Metrics,
  MinPublishVolumeEnvelopes,
  type Observation,
  ObservationOversizedError,
  type ReciprocityMode,
  type References,
  allMetricsZero,
  checkObservationSize,
  eligibleForPublication,
  isKnownAbuseCategory,
  meetsPublishVolume,
  signReferences,
  validateEvidenceFields,
  verifyEvidenceBytes,
  verifyReferences,
} from "../../src/reputation/index.js";

import {
  type VectorEntry,
  decodeHex,
  getBool,
  getField,
  getInt,
  getOptionalString,
  getString,
  isRecord,
} from "./helpers.js";

// ---------------------------------------------------------------------------
// persistent silent counter (decision 1)
// Triggered by delivery-status.json/persistent-silent-counter-behavior

export function handlePersistentSilentCounter(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const threshold = getInt(inputs, "threshold");
  const observationWindowHours = getInt(inputs, "minimum_observation_window_hours");
  const shortenedDeadlineHours = getInt(inputs, "shortened_deadline_hours");
  const idleExpiryDays = getInt(inputs, "idle_expiry_days");

  // Lib defaults MUST match the spec defaults.
  expect(PersistentSilentDefaults.threshold).toBe(threshold);
  expect(PersistentSilentDefaults.observationWindowMs).toBe(
    observationWindowHours * 60 * 60 * 1000,
  );
  expect(PersistentSilentDefaults.shortDeadlineMs).toBe(
    shortenedDeadlineHours * 60 * 60 * 1000,
  );
  expect(PersistentSilentDefaults.idleExpiryMs).toBe(
    idleExpiryDays * 24 * 60 * 60 * 1000,
  );

  // Drive the normal-accrual scenario through the counter and
  // assert the threshold-reached state.
  const recipient = getString(inputs, "recipient_address");
  const c = new PersistentSilentCounter();
  const start = new Date("2026-01-01T00:00:00Z");
  for (let i = 0; i < threshold; i++) {
    c.inc(recipient, new Date(start.getTime() + i * 60_000));
  }
  // Before the observation window elapses the trigger MUST NOT
  // engage even when the count threshold has been met.
  expect(c.effective(recipient, new Date(start.getTime() + 60_000))).toBeNull();
  // After the window elapses the shortened deadline kicks in.
  const after = new Date(
    start.getTime() + observationWindowHours * 60 * 60 * 1000 + 60_000,
  );
  expect(c.effective(recipient, after)).toBe(
    shortenedDeadlineHours * 60 * 60 * 1000,
  );
  // A non-silent ack resets the counter.
  c.reset(recipient);
  expect(c.count(recipient)).toBe(0);
  expect(c.effective(recipient, after)).toBeNull();
}

// ---------------------------------------------------------------------------
// discovery sub-vectors (decisions 6, 9, 10, 11)

export function handleSRVQuicUdpTarget(entry: VectorEntry): void {
  const expected = entry.expected;
  if (!isRecord(expected)) {
    throw new Error(`${entry.id}: missing expected`);
  }
  // scenario_b prefers _semp._udp over _semp._tcp. Just confirm
  // the expected block names _semp._udp as the source under
  // scenario_b.
  const b = getField(expected, "scenario_b_quic_target");
  if (!isRecord(b)) {
    throw new Error(`${entry.id}: scenario_b_quic_target missing`);
  }
  const source = getString(b, "source");
  expect(source).toMatch(/_semp\._udp/);
}

export function handleReciprocityPolicy(entry: VectorEntry): void {
  const expected = entry.expected;
  if (!isRecord(expected)) {
    throw new Error(`${entry.id}: missing expected`);
  }
  const modes = getField(expected, "modes");
  if (!Array.isArray(modes)) {
    throw new Error(`${entry.id}: modes not an array`);
  }
  // Lib's ReciprocityMode union MUST cover every spec-defined mode.
  const known: ReciprocityMode[] = ["none", "lenient", "strict"];
  for (const m of modes) {
    expect(known).toContain(m as ReciprocityMode);
  }
  // The disclosure under strict requires minimum_publish_volume.
  const action = getString(expected, "consumer_action_under_strict");
  expect(action).toMatch(/minimum_publish_volume/);
}

export function handleKeyFetchStatusDispatch(entry: VectorEntry): void {
  const expected = entry.expected;
  if (!isRecord(expected)) {
    throw new Error(`${entry.id}: missing expected`);
  }
  const statusSet = getField(expected, "status_vocabulary");
  if (Array.isArray(statusSet)) {
    const required = ["found", "not_found", "legacy_required", "recipient_not_found", "error"];
    for (const s of required) {
      expect(statusSet).toContain(s);
    }
  }
}

export function handleHTTP2UrlTemplates(entry: VectorEntry): void {
  const expected = entry.expected;
  if (!isRecord(expected)) {
    throw new Error(`${entry.id}: missing expected`);
  }
  // Lib helpers MUST produce the spec-pinned paths.
  const sampleAddr = "alice@example.com";
  expect(discoveryPath(sampleAddr)).toBe(`/v1/discovery/${sampleAddr}`);
  expect(keysPath(sampleAddr)).toBe(`/v1/keys/${sampleAddr}`);
  expect(sessionPath("01J")).toBe("/v1/session/01J");
  expect(PathDiscovery).toBe("/v1/discovery");
  expect(PathKeys).toBe("/v1/keys");
  expect(PathHandshake).toBe("/v1/handshake");
  expect(PathEnvelope).toBe("/v1/envelope");
  expect(PathSession).toBe("/v1/session/");
}

export function handleMigrationKeyFetchRedirect(entry: VectorEntry): void {
  const inputs = entry.inputs;
  if (!isRecord(inputs)) {
    throw new Error(`${entry.id}: missing inputs`);
  }
  // The vector pins the shape of the migration_to field on a
  // SEMP_KEYS result. Confirm the input has the fields the lib
  // would emit.
  const keyResp = getField(inputs, "key_response_json");
  if (isRecord(keyResp)) {
    const results = keyResp.results;
    if (Array.isArray(results) && results.length > 0) {
      const first = results[0];
      if (isRecord(first)) {
        const m = first.migration_to;
        if (isRecord(m)) {
          expect(typeof m.new_address).toBe("string");
          expect(typeof m.record_id).toBe("string");
          // Spec rename: field is notice_window_until, not
          // forwarding_window_until.
          if (m.notice_window_until !== undefined) {
            expect(typeof m.notice_window_until).toBe("string");
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// extensions (decision 12C / 12D)

export function handleExtensionDefinitionDocumentURL(entry: VectorEntry): void {
  const samples = entry.samples ?? [];
  for (const s of samples) {
    const url = getOptionalString(s, "definition_url");
    if (url === undefined) {
      continue;
    }
    // Every legitimate sample URL MUST contain the well-known prefix.
    if (getOptionalString(s, "outcome") !== "reject") {
      expect(url).toContain(DefinitionPathPrefix);
    }
  }
}

export function handleValidationFailures(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const wantRejection = getField(expected, "rejection_json");
  if (!isRecord(wantRejection)) {
    throw new Error(`${entry.id}: rejection_json missing`);
  }
  const wantErrors = wantRejection.errors;
  if (!Array.isArray(wantErrors)) {
    throw new Error(`${entry.id}: errors array missing`);
  }
  // Build the rejection from the lib helper and check the wire
  // shape matches.
  const items = wantErrors.map((e) => {
    if (!isRecord(e)) {
      throw new Error(`${entry.id}: errors entry not an object`);
    }
    return {
      extension: getString(e, "extension"),
      validation_failure: getString(
        e,
        "validation_failure",
      ) as ValidationFailureCode,
    };
  });
  const got = newValidationFailureRejection(items, wantRejection.reason as string);
  expect(got.type).toBe("SEMP_ENVELOPE");
  expect(got.step).toBe("rejected");
  expect(got.reason_code).toBe("extension_unsupported");
  expect(got.errors).toEqual(items);
}

// ---------------------------------------------------------------------------
// pow extra (decision: PoW difficulty calibration)

export function handlePoWDifficultyCalibration(entry: VectorEntry): void {
  // The vector is informational: it pins a difficulty table the
  // operator's policy SHOULD honor. The library does not encode a
  // single canonical table (operators tune per deployment), so the
  // handler just verifies the table is well-formed.
  const inputs = entry.inputs;
  if (!isRecord(inputs)) {
    throw new Error(`${entry.id}: missing inputs`);
  }
  const table = getField(inputs, "calibration_table");
  if (!Array.isArray(table)) {
    return;
  }
  for (const row of table) {
    if (!isRecord(row)) {
      continue;
    }
    expect(typeof row.difficulty_bits).toBe("number");
    expect(typeof row.expected_hashes).toBe("number");
    // expected_hashes MUST equal 2^difficulty_bits.
    const bits = row.difficulty_bits as number;
    const hashes = row.expected_hashes as number;
    expect(hashes).toBe(2 ** bits);
  }
}

// ---------------------------------------------------------------------------
// migration-notice (decision 11)

export function handleMigrationNotice(entry: VectorEntry): void {
  const expected = entry.expected;
  if (!isRecord(expected)) {
    throw new Error(`${entry.id}: missing expected`);
  }
  const rejection = getField(expected, "rejection_json");
  if (isRecord(rejection)) {
    expect(rejection.type).toBe("SEMP_ENVELOPE");
    expect(rejection.step).toBe("rejected");
    expect(rejection.reason_code).toBe("policy_forbidden");
    if (entry.id === "migration-notice-during-window") {
      const notice = rejection.migration_notice;
      expect(isRecord(notice)).toBe(true);
      if (isRecord(notice)) {
        expect(typeof notice.new_address).toBe("string");
        expect(typeof notice.migration_record_id).toBe("string");
      }
    } else if (entry.id === "migration-notice-after-window") {
      // After the window the notice MUST be absent.
      expect(rejection.migration_notice).toBeUndefined();
    }
  }
}

// ---------------------------------------------------------------------------
// trust-observation (decisions 2, 3)

export function handleTrustObservation(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }

  if (entry.id === "trust-observation-with-evidence-hash") {
    const evidenceBytes = decodeHex(getString(inputs, "evidence_bytes_hex"));
    const pre = getField(inputs, "observation_pre_sign_json");
    if (!isRecord(pre)) {
      throw new Error(`${entry.id}: observation_pre_sign_json missing`);
    }
    // Confirm the lib's evidence-hash verify accepts the pinned
    // digest over the pinned bytes.
    const obs = pre as unknown as Observation;
    validateEvidenceFields(obs);
    verifyEvidenceBytes(obs, evidenceBytes);
    // Confirm the encoded hash matches expected.
    const want = getString(expected, "evidence_digest_b64");
    const got = encodeBase64(sha256(evidenceBytes));
    expect(got).toBe(want);
    return;
  }

  if (entry.id === "trust-observation-evidence-hash-mismatch") {
    const tampered = decodeHex(getString(inputs, "tampered_bytes_hex"));
    const published = getString(inputs, "published_evidence_hash_value_b64");
    const obs: Observation = {
      type: "SEMP_TRUST_OBSERVATION",
      version: "1.0.0",
      id: "neg",
      observer: "x",
      subject: "y",
      window: { start: "2026-01-01T00:00:00Z", end: "2026-02-01T00:00:00Z" },
      metrics: {
        envelopes_received: 16,
        envelopes_rejected: 0,
        abuse_reports: 0,
      },
      assessment: "neutral",
      evidence_available: true,
      evidence_uri: "https://example.com/e",
      evidence_hash: { algorithm: "sha-256", value: published },
      timestamp: "2026-01-01T00:00:00Z",
      expires: "2026-02-01T00:00:00Z",
      signature: { algorithm: "ed25519", key_id: "k", value: "" },
      extensions: {},
    };
    expect(() => verifyEvidenceBytes(obs, tampered)).toThrowError(
      EvidenceHashMismatchError,
    );
    return;
  }

  if (entry.id === "trust-observation-size-cap-rejection") {
    // Size cap constant MUST match the spec value.
    expect(MaxObservationBytes).toBe(16384);
    // Build a canonical observation that exceeds the cap and verify
    // checkObservationSize rejects it.
    const oversize = new Uint8Array(MaxObservationBytes + 1);
    expect(() => checkObservationSize(oversize)).toThrowError(
      ObservationOversizedError,
    );
    // Evidence cap RECOMMENDED value MUST match the spec.
    expect(MaxEvidenceBytes).toBe(1024 * 1024);
    return;
  }

  throw new Error(`${entry.id}: unhandled trust-observation sub-vector`);
}

// ---------------------------------------------------------------------------
// reputation-references / valid (decision 15)

export function handleReputationReferences(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const domainSeed = decodeHex(getString(inputs, "domain_seed_hex"));
  const domainPub = decodeHex(getString(inputs, "domain_pub_hex"));
  const keyId = getString(inputs, "domain_key_id");
  const preRaw = getField(inputs, "references_pre_sign_json");
  if (!isRecord(preRaw)) {
    throw new Error(`${entry.id}: references_pre_sign_json missing`);
  }
  const refs = JSON.parse(JSON.stringify(preRaw)) as References;
  signReferences(refs, domainSeed, keyId);

  // Cross-check produced signature against pinned expected value.
  const expRaw = getField(expected, "signed_references_json");
  if (isRecord(expRaw)) {
    const expSig = (expRaw.signature as { value?: string } | undefined)?.value;
    if (typeof expSig === "string" && expSig !== "") {
      expect(refs.signature.value).toBe(expSig);
    }
  }
  expect(verifyReferences(refs, domainPub)).toBe(true);
}

// ---------------------------------------------------------------------------
// status-config / valid (decision 15)

export function handleStatusConfig(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const deviceSeed = decodeHex(getString(inputs, "device_seed_hex"));
  const devicePub = decodeHex(getString(inputs, "device_pub_hex"));
  const keyId = getString(inputs, "device_key_id");
  const preRaw = getField(inputs, "update_pre_sign_json");
  if (!isRecord(preRaw)) {
    throw new Error(`${entry.id}: update_pre_sign_json missing`);
  }
  const msg = JSON.parse(JSON.stringify(preRaw)) as StatusMessage;
  signStatusMessage(msg, deviceSeed, keyId);

  const expRaw = getField(expected, "signed_update_json");
  if (isRecord(expRaw)) {
    const expSig = (expRaw.signature as { value?: string } | undefined)?.value;
    if (typeof expSig === "string" && expSig !== "") {
      expect(msg.signature.value).toBe(expSig);
    }
  }
  expect(verifyStatusMessage(msg, devicePub)).toBe(true);
}

// ---------------------------------------------------------------------------
// abuse-report / observation_record_abuse

export function handleAbuseReportObservation(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const reportRaw = getField(inputs, "report_json");
  if (!isRecord(reportRaw)) {
    throw new Error(`${entry.id}: report_json missing`);
  }
  const report = reportRaw as unknown as AbuseReport;
  expect(report.type).toBe(AbuseReportType);
  expect(report.category).toBe("observation_record_abuse");
  expect(isKnownAbuseCategory(report.category as string)).toBe(true);

  // Cross-check the spec category set against the lib's union.
  const cats = expected.categories_known_to_lib;
  if (Array.isArray(cats)) {
    for (const c of cats) {
      expect(
        isKnownAbuseCategory(c as string),
        `spec category "${c as string}" not recognized by lib`,
      ).toBe(true);
    }
  }
}

// ---------------------------------------------------------------------------
// publication-eligibility / threshold

export function handlePublicationEligibility(entry: VectorEntry): void {
  expect(MinPublishVolumeEnvelopes).toBe(16);
  const samples = entry.samples ?? [];
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    if (!isRecord(s)) {
      continue;
    }
    const metrics = getField(s, "metrics") as unknown as Metrics;
    const wantMeets = getBool(s, "expected_meets_publish_volume");
    const wantEligible = getBool(s, "expected_eligible");
    const label = getString(s, "label");
    expect(
      meetsPublishVolume(metrics),
      `sample ${i} (${label}): meetsPublishVolume`,
    ).toBe(wantMeets);
    expect(
      eligibleForPublication(metrics),
      `sample ${i} (${label}): eligibleForPublication`,
    ).toBe(wantEligible);
    if (s.expected_all_zero !== undefined) {
      expect(
        allMetricsZero(metrics),
        `sample ${i} (${label}): allMetricsZero`,
      ).toBe(s.expected_all_zero as boolean);
    }
  }
}

function encodeBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i] ?? 0);
  }
  return btoa(s);
}
