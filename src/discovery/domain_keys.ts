/**
 * Domain key publication parsing per DISCOVERY.md §3.3.
 *
 * Federation peers fetch the domain signing + encryption keys from
 * the URL advertised as `endpoints.domain_keys` in a server's
 * configuration document. The HTTPS certificate chain is the trust
 * anchor: if the TLS certificate is valid for the hostname, the
 * domain keys it publishes are trusted (§3.3 paragraph 4).
 *
 * Beyond the TLS check, peers MUST cross-verify that
 * `signing_key.key_id` is the SHA-256 fingerprint of the published
 * `signing_key.public_key`. Otherwise a misconfigured server (or an
 * attacker on the publication path) could swap in a key whose
 * fingerprint doesn't match the one the peer cached. This module
 * exposes that check as {@link verifyDomainKeyFingerprint}.
 *
 * @module
 */

import { fingerprint as computeFingerprint } from "../keys/index.js";

import {
  isRecord,
  requireString,
} from "./configuration.js";

/** `type` discriminator for a domain-keys document. */
export const DomainKeysType = "SEMP_DOMAIN_KEYS";

/** Maximum byte size accepted for a fetched domain-keys body. */
export const DomainKeysMaxBytes = 32 * 1024;

/** A single algorithm-tagged public key block. */
export interface KeyBlock {
  algorithm: string;
  /** Base64-encoded raw public key bytes. */
  public_key: string;
  /** SHA-256 fingerprint of the raw public key bytes, hex-encoded. */
  key_id: string;
}

/** Parsed domain-keys document per §3.3. */
export interface DomainKeys {
  type: typeof DomainKeysType;
  version: string;
  domain: string;
  signing_key: KeyBlock;
  encryption_key: KeyBlock;
  /** Forward-compatible: unknown fields preserved. */
  [key: string]: unknown;
}

/**
 * Validate and narrow a parsed JSON value into a {@link DomainKeys}.
 * Does NOT perform the fingerprint cross-check; call
 * {@link verifyDomainKeyFingerprint} on each {@link KeyBlock} after
 * parsing.
 */
export function parseDomainKeys(value: unknown): DomainKeys {
  if (!isRecord(value)) {
    throw new Error("domain_keys: not a JSON object");
  }
  if (value.type !== DomainKeysType) {
    throw new Error(
      `domain_keys: type ${JSON.stringify(value.type)}, want ${DomainKeysType}`,
    );
  }
  requireString(value, "version");
  requireString(value, "domain");

  if (!isRecord(value.signing_key)) {
    throw new Error("domain_keys: signing_key: missing or not an object");
  }
  validateKeyBlock(value.signing_key, "signing_key");

  if (!isRecord(value.encryption_key)) {
    throw new Error("domain_keys: encryption_key: missing or not an object");
  }
  validateKeyBlock(value.encryption_key, "encryption_key");

  return value as unknown as DomainKeys;
}

function validateKeyBlock(obj: Record<string, unknown>, label: string): void {
  if (typeof obj.algorithm !== "string" || obj.algorithm === "") {
    throw new Error(`domain_keys: ${label}.algorithm: missing`);
  }
  if (typeof obj.public_key !== "string" || obj.public_key === "") {
    throw new Error(`domain_keys: ${label}.public_key: missing`);
  }
  if (typeof obj.key_id !== "string" || obj.key_id === "") {
    throw new Error(`domain_keys: ${label}.key_id: missing`);
  }
}

/**
 * Decode `block.public_key` from base64. The caller asserts the
 * algorithm is one whose raw key is a fixed size (32 bytes for both
 * Ed25519 signing and X25519 encryption); this helper does not
 * enforce a length.
 */
export function decodeKeyBlockPublic(block: KeyBlock): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(block.public_key, "base64"));
  }
  const bin = atob(block.public_key);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * Cross-check that `block.key_id` is the lowercase-hex SHA-256
 * fingerprint of the decoded `block.public_key`. Returns true when
 * the binding holds. Production callers MUST use this on every
 * fetched {@link DomainKeys} before trusting either key.
 */
export function verifyDomainKeyFingerprint(block: KeyBlock): boolean {
  const pub = decodeKeyBlockPublic(block);
  const want = computeFingerprint(pub);
  return block.key_id.toLowerCase() === want;
}
