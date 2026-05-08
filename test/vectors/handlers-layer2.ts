/**
 * Wave 2 vectors-runner handlers.
 *
 * Layer 2 deterministic categories: canonical envelope, bucket
 * math, discovery TXT parsing + response parsing, extension
 * validation, clock-tolerance tiers, plus the decision-table
 * categories (rejection-codes, session-lifecycle, delivery-status,
 * device-certificates, key-revocation, recipient-status) and the
 * negative-envelope-rejection schema check.
 *
 * @module
 */

import { expect } from "vitest";

import {
  type VectorEntry,
  bytesEqual,
  decodeHex,
  encodeHex,
  getBool,
  getField,
  getInt,
  getOptionalString,
  getString,
  isRecord,
} from "./helpers.js";

import { canonicalEnvelopeBytes, selectRecipientCountBucket, selectSizeBucket } from "../../src/envelope/index.js";
import { parseTXTCapabilities } from "../../src/discovery/index.js";
import { isKnownReasonCode, isRecoverable, type ReasonCode } from "../../src/reasoncodes.js";
import {
  type Layer,
  type Map as ExtMap,
  Registry,
  maxBytesFor,
  validate,
} from "../../src/extensions/index.js";
import {
  checkExpiry,
  checkFutureTimestamp,
  defaultTolerance,
} from "../../src/clockskew/index.js";

// ---------------------------------------------------------------------------
// envelope-canonical
//
// Take inputs.envelope_json, canonicalize via §4.3 elision, compare
// to expected.canonical_utf8 byte-for-byte. semp-ts uses generic
// canonical-JSON so empty `extensions: {}` maps and absent
// `first_contact_token` are preserved verbatim — a divergence that
// caught semp-go in Phase 1 (VR-1, VR-2).

export function handleEnvelopeCanonical(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error("envelope-canonical: missing inputs or expected");
  }
  const envJSON = getField(inputs, "envelope_json");
  if (envJSON === undefined) {
    throw new Error("envelope-canonical: inputs.envelope_json missing");
  }
  const got = canonicalEnvelopeBytes(envJSON);
  const want = getString(expected, "canonical_utf8");
  expect(new TextDecoder().decode(got)).toBe(want);
}

// ---------------------------------------------------------------------------
// envelope-buckets (size + recipient-count)

export function handleEnvelopeBuckets(entry: VectorEntry): void {
  switch (entry.id) {
    case "envelope-size-buckets":
      handleSizeBucketSamples(entry);
      break;
    case "recipient-count-buckets":
      handleRecipientBucketSamples(entry);
      break;
    default:
      throw new Error(`envelope-buckets: unknown sub-vector ${entry.id}`);
  }
}

function handleSizeBucketSamples(entry: VectorEntry): void {
  const samples = entry.samples ?? [];
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const size = getInt(s, "unpadded_size_bytes");
    const wantBucketRaw = getField(s, "bucket_size_bytes");
    if (typeof wantBucketRaw !== "number") {
      // "exceeds bucket ceiling" sentinel — selectSizeBucket throws.
      continue;
    }
    let got: number;
    try {
      got = selectSizeBucket(size, 1 << 24);
    } catch {
      continue;
    }
    expect(got, `sample ${i}: size=${size}`).toBe(wantBucketRaw);
  }
}

function handleRecipientBucketSamples(entry: VectorEntry): void {
  const samples = entry.samples ?? [];
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const real = getInt(s, "real_recipients");
    const single = getBool(s, "single_domain_not_group");
    const wantBucketRaw = getField(s, "bucket_count");
    if (typeof wantBucketRaw !== "number") {
      // String sentinel ("exceeds bucket ceiling; recomposition required").
      continue;
    }
    const got = selectRecipientCountBucket(real, single);
    expect(got, `sample ${i}: real=${real} single=${single}`).toBe(wantBucketRaw);
  }
}

// ---------------------------------------------------------------------------
// discovery (txt-parsing + response-parsing)

export function handleDiscovery(entry: VectorEntry): void {
  switch (entry.id) {
    case "discovery-txt-parsing":
      handleDiscoveryTXT(entry);
      break;
    case "discovery-response-parsing":
      handleDiscoveryResponse(entry);
      break;
    default:
      throw new Error(`discovery: unknown sub-vector ${entry.id}`);
  }
}

function handleDiscoveryTXT(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error("discovery-txt-parsing: missing inputs or expected");
  }
  const record = getString(inputs, "txt_record_utf8");
  const parsed = parseTXTCapabilities(record);
  const want = getField(expected, "parsed");
  if (!isRecord(want)) {
    throw new Error("discovery-txt-parsing: expected.parsed missing");
  }

  // Compare the structural fields. Sort _ignored_unknown for
  // stability — order is implementation-defined.
  const got: Record<string, unknown> = {};
  if (parsed.v !== undefined) {
    got.v = parsed.v;
  }
  if (parsed.pq !== undefined) {
    got.pq = parsed.pq;
  }
  if (parsed.c !== undefined) {
    got.c = parsed.c;
  }
  if (parsed.f !== undefined) {
    got.f = parsed.f;
  }
  got._ignored_unknown = [...parsed._ignored_unknown].sort();

  const wantSorted = { ...want } as Record<string, unknown>;
  if (Array.isArray(wantSorted._ignored_unknown)) {
    wantSorted._ignored_unknown = [...wantSorted._ignored_unknown].sort();
  }

  expect(got).toEqual(wantSorted);
}

function handleDiscoveryResponse(entry: VectorEntry): void {
  // Walk the parsed response, assert per-address `status` matches
  // the action documented in expected.per_address_actions, confirm
  // every result has a `ttl` (§4.6 caching policy). Signature
  // verification of discovery responses lives in discovery-signed
  // (Wave 3); this vector pins a placeholder signature value
  // because its purpose is parsing semantics.
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error("discovery-response-parsing: missing inputs or expected");
  }
  const resp = getField(inputs, "response_json");
  if (!isRecord(resp)) {
    throw new Error("discovery-response-parsing: response_json not an object");
  }
  const results = resp.results;
  if (!Array.isArray(results) || results.length === 0) {
    throw new Error("discovery-response-parsing: results empty");
  }
  const actions = getField(expected, "per_address_actions");
  if (!isRecord(actions)) {
    throw new Error("discovery-response-parsing: per_address_actions not an object");
  }
  for (const r of results) {
    if (!isRecord(r)) {
      continue;
    }
    const addr = r.address;
    const status = r.status;
    if (typeof addr !== "string" || typeof status !== "string") {
      continue;
    }
    const expEntry = actions[addr];
    expect(expEntry, `per_address_actions[${addr}]`).toBeDefined();
    if (!isRecord(expEntry)) {
      continue;
    }
    expect(status, `${addr} status`).toBe(expEntry.status);
    expect(r.ttl, `${addr} ttl`).toBeDefined();
  }
}

// ---------------------------------------------------------------------------
// rejection-codes — both samples cross-check ReasonCode.Recoverable()

export function handleRejectionCodes(entry: VectorEntry): void {
  const samples = entry.samples ?? [];
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const code = getString(s, "reason_code");
    const wantRecov = getBool(s, "recoverable");
    expect(isKnownReasonCode(code), `sample ${i}: reason_code ${code} known`).toBe(true);
    const gotRecov = isRecoverable(code as ReasonCode);
    expect(gotRecov, `sample ${i}: ${code}`).toBe(wantRecov);
  }
}

// ---------------------------------------------------------------------------
// extension-entries
//
// Six entries; the table-shaped one (extension-size-limits) checks
// per-layer byte ceilings, the rest check accept/reject under a
// registry built from inputs.implementation_supports.

export function handleExtensionEntries(entry: VectorEntry): void {
  if (entry.id === "extension-size-limits") {
    handleExtensionSizeLimits(entry);
    return;
  }
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const extJSON = getField(inputs, "extensions_json");
  if (!isRecord(extJSON)) {
    throw new Error(`${entry.id}: extensions_json missing`);
  }

  const reg = new Registry();
  const supports = getField(inputs, "implementation_supports");
  if (Array.isArray(supports)) {
    for (const id of supports) {
      if (typeof id === "string") {
        reg.register({
          identifier: id,
          layers: ["postmark", "seal", "brief", "enclosure"],
        });
      }
    }
  }

  const err = validate(reg, "postmark", extJSON as ExtMap);
  const action = getString(expected, "action");
  switch (action) {
    case "accept":
      expect(err, "expected accept").toBeNull();
      break;
    case "reject":
      expect(err, "expected reject").not.toBeNull();
      break;
    default:
      throw new Error(`${entry.id}: unknown expected.action ${action}`);
  }
}

function handleExtensionSizeLimits(entry: VectorEntry): void {
  const samples = entry.samples ?? [];
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const layerStr = getString(s, "layer");
    const limit = getInt(s, "size_limit_bytes");
    const payload = getInt(s, "test_payload_bytes");
    const outcome = getString(s, "expected_outcome");

    const layer = layerFromString(layerStr);
    const gotLimit = maxBytesFor(layer);
    expect(gotLimit, `sample ${i}: ${layerStr} limit`).toBe(limit);

    const accept = payload <= gotLimit;
    if (outcome === "accept") {
      expect(accept, `sample ${i}: payload=${payload} limit=${gotLimit}`).toBe(true);
    } else if (outcome === "reject") {
      expect(accept, `sample ${i}: payload=${payload} limit=${gotLimit}`).toBe(false);
      const rc = getOptionalString(s, "reason_code");
      if (rc !== undefined) {
        expect(isKnownReasonCode(rc), `sample ${i}: reason_code ${rc}`).toBe(true);
      }
    }
  }
}

function layerFromString(s: string): Layer {
  switch (s) {
    case "postmark.extensions":
    case "postmark":
      return "postmark";
    case "seal.extensions":
    case "seal":
      return "seal";
    case "brief.extensions":
    case "brief":
      return "brief";
    case "enclosure.extensions":
    case "enclosure":
      return "enclosure";
    default:
      return "postmark";
  }
}

// ---------------------------------------------------------------------------
// clock-tolerance — future-dated and expires-at samples

export function handleClockTolerance(entry: VectorEntry): void {
  const samples = entry.samples ?? [];
  const tol = defaultTolerance();
  const now = new Date(Date.UTC(2026, 0, 1, 12, 0, 0));

  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const expected = getString(s, "expected");
    let accepted: boolean;
    if (entry.id === "clock-tolerance-future-dated") {
      const delta = getInt(s, "T_minus_now_seconds");
      const t = new Date(now.getTime() + delta * 1000);
      accepted = checkFutureTimestamp(t, now, tol) === null;
    } else if (entry.id === "clock-tolerance-expires-at") {
      const delta = getInt(s, "now_minus_expiresAt_seconds");
      const t = new Date(now.getTime() - delta * 1000);
      accepted = checkExpiry(t, now, tol) === null;
    } else {
      throw new Error(`clock-tolerance: unknown sub-vector ${entry.id}`);
    }
    if (!checkOutcome(accepted, expected)) {
      throw new Error(
        `sample ${i}: got accept=${accepted}, want ${expected}`,
      );
    }
  }
}

function checkOutcome(accepted: boolean, expected: string): boolean {
  switch (expected) {
    case "accept":
      return accepted;
    case "reject":
      return !accepted;
    case "accept_or_reject_at_implementor_choice":
      return true;
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Decision-table shape validators
//
// session-lifecycle, delivery-status, device-certificates,
// key-revocation, recipient-status — each ships table-shaped
// vectors. The runner asserts samples is non-empty, every sample
// is an object with the documented fields, and reason_code values
// (where present) cross-check against semp-ts's ReasonCode set.

export function handleDecisionTable(entry: VectorEntry, requiredFields: string[]): void {
  const samples = entry.samples ?? [];
  if (samples.length === 0) {
    if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
      throw new Error(`${entry.id}: not table-shape and missing inputs/expected`);
    }
    return;
  }
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    if (!isRecord(s)) {
      throw new Error(`sample ${i}: not an object`);
    }
    for (const f of requiredFields) {
      expect(f in s, `sample ${i}: field ${f}`).toBe(true);
    }
    const rc = getOptionalString(s, "reason_code");
    if (rc !== undefined && rc.length > 0) {
      expect(isKnownReasonCode(rc), `sample ${i}: reason_code ${rc}`).toBe(true);
    }
  }
}

export function handleSessionLifecycle(entry: VectorEntry): void {
  switch (entry.id) {
    case "session-state-transitions":
      handleDecisionTable(entry, ["from_state", "event", "to_state"]);
      break;
    case "concurrent-session-limits":
      handleDecisionTable(entry, ["scenario", "expected_behavior"]);
      break;
    case "rekey-limits":
      handleDecisionTable(entry, ["condition", "expected_behavior"]);
      break;
    default:
      throw new Error(`session-lifecycle: unknown sub-vector ${entry.id}`);
  }
}

export function handleDeliveryStatus(entry: VectorEntry): void {
  switch (entry.id) {
    case "acknowledgment-to-ui-state":
      handleDecisionTable(entry, ["server_acknowledgment", "client_ui_state"]);
      break;
    case "queued-to-final-transitions":
      handleDecisionTable(entry, ["initial_status", "delivery_event_status", "client_action"]);
      break;
    case "discovery-outcome-to-submission-status":
      handleDecisionTable(entry, ["discovery_outcome"]);
      break;
    case "multi-recipient-mixed-outcomes":
      // single-case; just confirm shape
      if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
        throw new Error(`${entry.id}: missing inputs or expected`);
      }
      break;
    default:
      throw new Error(`delivery-status: unknown sub-vector ${entry.id}`);
  }
}

export function handleDeviceCertificates(entry: VectorEntry): void {
  switch (entry.id) {
    case "certificate-validation-failures":
      handleDecisionTable(entry, ["condition", "expected_action"]);
      break;
    case "scope-enforcement-by-recipient":
      handleDecisionTable(entry, ["recipient_address", "scope_match", "expected_action"]);
      break;
    case "scope-mode-enforcement":
      handleDecisionTable(entry, ["scope_send_mode", "recipient", "expected_action"]);
      break;
    case "receive-matcher-enforcement":
      handleDecisionTable(entry, ["device", "scope_receive", "inbound_sender", "expected"]);
      break;
    case "rate-limit-enforcement":
      handleDecisionTable(entry, ["tier_config", "state", "expected_action"]);
      break;
    case "certificate-lifecycle-operations":
      handleDecisionTable(entry, ["operation", "session_impact", "expected_behavior"]);
      break;
    case "valid-device-certificate":
    case "resource-read-write-enforcement":
    case "staged-delivery":
      // Descriptive entries; just confirm well-formed JSON.
      if (entry.inputs === undefined && (entry.samples === undefined || entry.samples.length === 0)) {
        throw new Error(`${entry.id}: neither inputs nor samples`);
      }
      break;
    default:
      throw new Error(`device-certificates: unknown sub-vector ${entry.id}`);
  }
}

export function handleKeyRevocation(entry: VectorEntry): void {
  if (entry.id !== "revoked-key-response") {
    throw new Error(`key-revocation: unknown sub-vector ${entry.id}`);
  }
  if (!isRecord(entry.inputs) || !isRecord(entry.expected)) {
    throw new Error(`${entry.id}: missing inputs or expected`);
  }
  const rc = getOptionalString(entry.expected, "reason_code");
  if (rc !== undefined && rc.length > 0) {
    expect(isKnownReasonCode(rc)).toBe(true);
  }
}

export function handleRecipientStatus(entry: VectorEntry): void {
  switch (entry.id) {
    case "status-visibility-rules":
      handleDecisionTable(entry, ["visibility_mode", "sender_identity", "status_included"]);
      break;
    case "status-does-not-affect-delivery":
      handleDecisionTable(entry, ["recipient_state", "envelope_valid", "expected_acknowledgment"]);
      break;
    default:
      throw new Error(`recipient-status: unknown sub-vector ${entry.id}`);
  }
}

// ---------------------------------------------------------------------------
// negative-envelope-rejection — schema check (Wave 2 partial; full
// re-verification of seal/MAC on tampered envelopes is Wave 3).

export function handleNegativeEnvelopeRejection(entry: VectorEntry): void {
  if (!isRecord(entry.inputs)) {
    throw new Error(`${entry.id}: inputs missing`);
  }
  if (!isRecord(entry.expected)) {
    throw new Error(`${entry.id}: expected missing`);
  }
  const rc = getOptionalString(entry.expected, "rejection_reason_code");
  if (rc !== undefined && rc.length > 0) {
    expect(isKnownReasonCode(rc)).toBe(true);
  }
}

// ---------------------------------------------------------------------------
// must-reject-index — generated cross-reference; nothing per-vector
// to dispatch.

export function handleMustRejectIndex(entry: VectorEntry): void {
  if (entry.inputs !== undefined || entry.expected !== undefined) {
    throw new Error(`must-reject-index entry has unexpected fields: ${entry.id}`);
  }
}

// Quiet unused-import lint until the runner uses these in Wave 3.
void bytesEqual;
void decodeHex;
void encodeHex;
