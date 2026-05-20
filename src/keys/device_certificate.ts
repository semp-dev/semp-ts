/**
 * Scoped device certificates per KEY.md §10.3.
 *
 * A `SEMP_DEVICE_CERTIFICATE` binds a delegated device's public key
 * to a permission scope and is signed by an existing full-access
 * device of the account (the issuer). The home server enforces the
 * scope on every relevant operation by the delegated device.
 *
 * This module provides:
 *
 *   - {@link DeviceCertificate} typed shape + the supporting
 *     {@link Scope}, {@link ScopeMatcher}, {@link ScopeResource},
 *     {@link ScopeEntry}, {@link RateLimitTier} types.
 *   - {@link signDeviceCertificate}: build + Ed25519-sign a certificate
 *     under the issuing device's signing seed (path
 *     `signature.value`, prefix `SEMP-DEVICE-AUTHORIZE:`).
 *   - {@link verifyDeviceCertificate}: Ed25519-verify against the
 *     issuer's published device public key.
 *   - {@link validateDeviceCertificate}: structural checks per
 *     §10.3.2 / §10.3.3 / §10.3.8 (lifetime cap, scope rules).
 *   - {@link scopeAllowsRecipient} / {@link scopeAllowsSender}:
 *     enforcement helpers that the home server invokes on each
 *     operation per §10.3.4.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "./signed.js";

/** `type` discriminator for a device certificate. */
export const DeviceCertificateType = "SEMP_DEVICE_CERTIFICATE";

/** Domain-separation prefix for the issuer signature, per ENVELOPE.md §4.3. */
export const DeviceAuthorizePrefix = "SEMP-DEVICE-AUTHORIZE:";

/** Combined cap on `allow + deny` size in a single matcher per §10.3.3.1. */
export const MaxScopeMatcherEntries = 10_000;

/** Cap on rate-limit tiers per scope field per §10.3.3.3. */
export const MaxScopeRateLimitTiers = 16;

/** Cap on certificate lifetime per §10.3.8: 365 days, in milliseconds. */
export const MaxDeviceCertificateLifetimeMs = 365 * 24 * 3600 * 1000;

/** Matcher modes per §10.3.3.1. */
export type MatcherMode = "unrestricted" | "restricted" | "denylist" | "none";

/** Entity types per DELIVERY.md §5.3, reused in scope entries. */
export type EntityType = "user" | "domain" | "server";

/** One entry in a matcher's `allow` or `deny` list. */
export interface ScopeEntry {
  type: EntityType;
  /** Required when `type === "user"`: full SEMP address. */
  address?: string;
  /** Required when `type === "domain"` or `type === "server"`. */
  domain?: string;
  /** Required when `type === "server"` (semp-go uses `domain`; this matches the spec). */
  server?: string;
}

/** Rate-limit tier per §10.3.3.3. */
export interface RateLimitTier {
  /** Rolling-window length, MUST be >= 1. */
  period_seconds: number;
  /** Max ops per window, MUST be >= 0. */
  amount_allowed: number;
}

/** Matcher-shape permission per §10.3.3.1, used by `scope.send` and `scope.receive`. */
export interface ScopeMatcher {
  mode: MatcherMode;
  allow?: ScopeEntry[];
  deny?: ScopeEntry[];
  rate_limits: RateLimitTier[];
  /** Present only on `scope.receive`. Positive integer, position in staged delivery. */
  delivery_stage?: number;
}

/** Resource-shape permission per §10.3.3.2, used by blocklist/keys/devices. */
export interface ScopeResource {
  read: boolean;
  write: boolean;
  rate_limits: RateLimitTier[];
}

/** Five-field scope object per §10.3.3. */
export interface Scope {
  send: ScopeMatcher;
  receive: ScopeMatcher;
  blocklist: ScopeResource;
  keys: ScopeResource;
  devices: ScopeResource;
}

/** Issuer signature block. */
export interface CertificateSignature {
  algorithm: string;
  key_id: string;
  value: string;
}

/** SEMP_DEVICE_CERTIFICATE record per §10.3.1. */
export interface DeviceCertificate {
  type: typeof DeviceCertificateType;
  version: string;
  device_id: string;
  device_public_key: string;
  account: string;
  issued_by: string;
  issued_at: string;
  expires_at: string;
  scope: Scope;
  signature: CertificateSignature;
}

/** Inputs to {@link signDeviceCertificate}. */
export interface SignDeviceCertificateInput {
  /** Pre-sign certificate; `signature.value` will be replaced. */
  certificate: DeviceCertificate;
  /** 32-byte Ed25519 secret seed for the issuing device. */
  issuerSigningSeed: Uint8Array;
  /** Lowercase-hex SHA-256 fingerprint of the issuing device public key. */
  issuerKeyId: string;
}

/** Result of a successful {@link signDeviceCertificate} call. */
export interface SignDeviceCertificateResult {
  certificate: DeviceCertificate;
  signatureB64: string;
}

/**
 * Compute the issuer's signature over the canonical certificate
 * bytes, then return a copy with `signature.{algorithm,key_id,value}`
 * populated. Pre-populates the algorithm + key_id BEFORE
 * canonicalization so the canonical bytes cover both - an attacker
 * cannot downgrade the signing algorithm or forge a different
 * issuer fingerprint.
 */
export function signDeviceCertificate(
  input: SignDeviceCertificateInput,
): SignDeviceCertificateResult {
  if (input.issuerKeyId === "") {
    throw new Error("device certificate: empty issuer key_id");
  }

  validateDeviceCertificate(input.certificate, { skipSignatureCheck: true });

  const preSign: DeviceCertificate = {
    ...input.certificate,
    signature: {
      algorithm: "ed25519",
      key_id: input.issuerKeyId,
      value: "",
    },
  };

  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: preSign as unknown as Record<string, unknown>,
    seed: input.issuerSigningSeed,
    signaturePath: "signature.value",
    prefix: DeviceAuthorizePrefix,
  });

  return {
    certificate: signedJSON as unknown as DeviceCertificate,
    signatureB64,
  };
}

/**
 * Ed25519-verify a certificate's signature under `issuerPub`. Returns
 * true when the signature verifies. Does NOT cross-check that the
 * issuer is currently a registered, non-revoked full-access device
 * for the account - that requires a key directory store and is the
 * caller's responsibility.
 */
export function verifyDeviceCertificate(
  certificate: DeviceCertificate,
  issuerPub: Uint8Array,
): boolean {
  validateDeviceCertificate(certificate);
  if (certificate.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: certificate as unknown as Record<string, unknown>,
    publicKey: issuerPub,
    signaturePath: "signature.value",
    prefix: DeviceAuthorizePrefix,
  });
  return ok;
}

/** Options for {@link validateDeviceCertificate}. */
export interface ValidateOptions {
  /**
   * When true, don't require `signature.value` to be a non-empty
   * string. Used during the compose path before signing.
   */
  skipSignatureCheck?: boolean;
}

/**
 * Structural validation per §10.3.2 / §10.3.3 / §10.3.8. Throws on
 * the first violation. Does NOT verify the signature; pair with
 * {@link verifyDeviceCertificate}.
 */
export function validateDeviceCertificate(
  c: DeviceCertificate,
  opts: ValidateOptions = {},
): void {
  if (c.type !== DeviceCertificateType) {
    throw new Error(
      `device certificate: type ${JSON.stringify(c.type)}, want ${DeviceCertificateType}`,
    );
  }
  if (typeof c.version !== "string" || c.version === "") {
    throw new Error("device certificate: missing version");
  }
  for (const f of ["device_id", "device_public_key", "account", "issued_by"] as const) {
    if (typeof c[f] !== "string" || c[f] === "") {
      throw new Error(`device certificate: missing ${f}`);
    }
  }
  for (const f of ["issued_at", "expires_at"] as const) {
    if (typeof c[f] !== "string" || c[f] === "") {
      throw new Error(`device certificate: missing ${f}`);
    }
  }

  const issued = Date.parse(c.issued_at);
  const expires = Date.parse(c.expires_at);
  if (Number.isNaN(issued)) {
    throw new Error(`device certificate: issued_at is not ISO 8601: ${c.issued_at}`);
  }
  if (Number.isNaN(expires)) {
    throw new Error(`device certificate: expires_at is not ISO 8601: ${c.expires_at}`);
  }
  if (expires <= issued) {
    throw new Error("device certificate: expires_at MUST be after issued_at");
  }
  if (expires - issued > MaxDeviceCertificateLifetimeMs) {
    throw new Error(
      `device certificate: lifetime ${expires - issued} ms exceeds 365-day cap (KEY.md §10.3.8)`,
    );
  }

  validateScope(c.scope);

  if (typeof c.signature?.algorithm !== "string" || c.signature.algorithm === "") {
    throw new Error("device certificate: missing signature.algorithm");
  }
  if (typeof c.signature?.key_id !== "string" || c.signature.key_id === "") {
    throw new Error("device certificate: missing signature.key_id");
  }
  if (typeof c.signature?.value !== "string") {
    throw new Error("device certificate: signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && c.signature.value === "") {
    throw new Error("device certificate: signature.value is empty (unsigned)");
  }
}

/** Structural validation of a {@link Scope} per §10.3.3. */
export function validateScope(scope: Scope): void {
  if (scope === undefined || scope === null) {
    throw new Error("scope: missing");
  }
  validateMatcher(scope.send, "scope.send", false);
  validateMatcher(scope.receive, "scope.receive", true);
  validateResource(scope.blocklist, "scope.blocklist");
  validateResource(scope.keys, "scope.keys");
  validateResource(scope.devices, "scope.devices");
}

function validateMatcher(
  m: ScopeMatcher,
  path: string,
  allowDeliveryStage: boolean,
): void {
  if (m === undefined || m === null) {
    throw new Error(`${path}: missing`);
  }
  if (!Array.isArray(m.rate_limits)) {
    throw new Error(`${path}.rate_limits: missing or not an array`);
  }
  validateRateLimits(m.rate_limits, `${path}.rate_limits`);

  const allow = m.allow ?? [];
  const deny = m.deny ?? [];
  switch (m.mode) {
    case "unrestricted":
    case "none":
      if (allow.length > 0 || deny.length > 0) {
        throw new Error(
          `${path}: mode=${m.mode} requires allow + deny absent or empty`,
        );
      }
      break;
    case "restricted":
      if (allow.length === 0) {
        throw new Error(`${path}: mode=restricted requires non-empty allow`);
      }
      if (deny.length > 0) {
        throw new Error(`${path}: mode=restricted forbids deny`);
      }
      break;
    case "denylist":
      if (deny.length === 0) {
        throw new Error(`${path}: mode=denylist requires non-empty deny`);
      }
      if (allow.length > 0) {
        throw new Error(`${path}: mode=denylist forbids allow`);
      }
      break;
    default:
      throw new Error(`${path}: invalid mode ${JSON.stringify(m.mode)}`);
  }

  if (allow.length + deny.length > MaxScopeMatcherEntries) {
    throw new Error(
      `${path}: allow + deny size ${allow.length + deny.length} exceeds cap ${MaxScopeMatcherEntries}`,
    );
  }
  for (let i = 0; i < allow.length; i++) {
    validateScopeEntry(allow[i] as ScopeEntry, `${path}.allow[${i}]`);
  }
  for (let i = 0; i < deny.length; i++) {
    validateScopeEntry(deny[i] as ScopeEntry, `${path}.deny[${i}]`);
  }

  if (m.delivery_stage !== undefined) {
    if (!allowDeliveryStage) {
      throw new Error(`${path}: delivery_stage MUST be omitted on send matcher`);
    }
    if (!Number.isInteger(m.delivery_stage) || m.delivery_stage < 1) {
      throw new Error(
        `${path}.delivery_stage: ${m.delivery_stage} MUST be a positive integer`,
      );
    }
  }
}

function validateScopeEntry(e: ScopeEntry, path: string): void {
  switch (e.type) {
    case "user":
      if (typeof e.address !== "string" || e.address === "") {
        throw new Error(`${path}: type=user requires address`);
      }
      break;
    case "domain":
      if (typeof e.domain !== "string" || e.domain === "") {
        throw new Error(`${path}: type=domain requires domain`);
      }
      break;
    case "server":
      // Spec allows either `server` or `domain` as the matching key on
      // server entries; the example schemas in DELIVERY.md §5.3 use
      // `server`, but the device-cert example uses `domain`. Accept
      // either.
      if (
        (typeof e.server !== "string" || e.server === "") &&
        (typeof e.domain !== "string" || e.domain === "")
      ) {
        throw new Error(`${path}: type=server requires server or domain`);
      }
      break;
    default:
      throw new Error(`${path}: invalid entity type ${JSON.stringify(e.type)}`);
  }
}

function validateResource(r: ScopeResource, path: string): void {
  if (r === undefined || r === null) {
    throw new Error(`${path}: missing`);
  }
  if (typeof r.read !== "boolean") {
    throw new Error(`${path}.read: must be boolean`);
  }
  if (typeof r.write !== "boolean") {
    throw new Error(`${path}.write: must be boolean`);
  }
  if (!Array.isArray(r.rate_limits)) {
    throw new Error(`${path}.rate_limits: missing or not an array`);
  }
  validateRateLimits(r.rate_limits, `${path}.rate_limits`);
}

function validateRateLimits(tiers: RateLimitTier[], path: string): void {
  if (tiers.length > MaxScopeRateLimitTiers) {
    throw new Error(
      `${path}: ${tiers.length} tiers exceeds cap ${MaxScopeRateLimitTiers}`,
    );
  }
  for (let i = 0; i < tiers.length; i++) {
    const t = tiers[i] as RateLimitTier;
    if (!Number.isInteger(t.period_seconds) || t.period_seconds < 1) {
      throw new Error(
        `${path}[${i}].period_seconds: ${t.period_seconds} MUST be >= 1`,
      );
    }
    if (!Number.isInteger(t.amount_allowed) || t.amount_allowed < 0) {
      throw new Error(
        `${path}[${i}].amount_allowed: ${t.amount_allowed} MUST be >= 0`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Scope enforcement helpers per §10.3.4

/** Sender / recipient address inputs for matcher checks. */
export interface AddressIdentity {
  /** Full SEMP address (e.g. `alice@example.com`). */
  address: string;
  /** Routing server hostname when known. */
  server?: string;
}

/**
 * Report whether `matcher` permits sending to `recipient` per
 * §10.3.3.1. Does NOT evaluate rate limits - the caller applies
 * rate-limit tiers separately per §10.3.4.
 */
export function scopeAllowsRecipient(
  matcher: ScopeMatcher,
  recipient: AddressIdentity,
): boolean {
  switch (matcher.mode) {
    case "unrestricted":
      return true;
    case "none":
      return false;
    case "restricted":
      return matchAny(matcher.allow ?? [], recipient);
    case "denylist":
      return !matchAny(matcher.deny ?? [], recipient);
    default:
      // Unknown mode - fail closed.
      return false;
  }
}

/**
 * Report whether `matcher` permits receiving from `sender` per
 * §10.3.3.1. Identical evaluation to {@link scopeAllowsRecipient};
 * separate name reads clearly at call sites.
 */
export function scopeAllowsSender(
  matcher: ScopeMatcher,
  sender: AddressIdentity,
): boolean {
  return scopeAllowsRecipient(matcher, sender);
}

function matchAny(entries: ScopeEntry[], addr: AddressIdentity): boolean {
  const peer = addr.address.toLowerCase();
  const peerDomain = peer.includes("@") ? peer.split("@").pop() ?? "" : "";
  const peerServer = (addr.server ?? "").toLowerCase();
  for (const entry of entries) {
    switch (entry.type) {
      case "user":
        if (
          typeof entry.address === "string" &&
          entry.address !== "" &&
          entry.address.toLowerCase() === peer
        ) {
          return true;
        }
        break;
      case "domain":
        if (
          typeof entry.domain === "string" &&
          entry.domain !== "" &&
          entry.domain.toLowerCase() === peerDomain
        ) {
          return true;
        }
        break;
      case "server": {
        const ent = (entry.server ?? entry.domain ?? "").toLowerCase();
        if (ent === "") {
          continue;
        }
        // Server entries match either the routing server hostname (when
        // known) or the recipient's domain (which is approximately the
        // server identity for direct-domain deployments).
        if (peerServer !== "" && ent === peerServer) {
          return true;
        }
        if (peerServer === "" && ent === peerDomain) {
          return true;
        }
        break;
      }
    }
  }
  return false;
}
