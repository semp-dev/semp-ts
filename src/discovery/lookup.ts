/**
 * SEMP_DISCOVERY signed lookup per DISCOVERY.md §4.
 *
 * Wire shape:
 *   - Request body: `{type, step="request", version, id, timestamp,
 *     addresses, extensions?}`
 *   - Response body: `{type, step="response", version, id, timestamp,
 *     results, signature, extensions?}`
 *
 * The response is signed by the answering server's domain signing
 * key with the `SEMP-DISCOVERY:` prefix per ENVELOPE.md §4.3.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

/** Wire-level constants. */
export const DiscoveryMessageType = "SEMP_DISCOVERY";
export const DiscoveryStepRequest = "request";
export const DiscoveryStepResponse = "response";
export const DiscoveryRecordVersion = "1.0.0";
export const DiscoverySignaturePrefix = "SEMP-DISCOVERY:";

/** §4.6 status values. */
export type DiscoveryStatus =
  | "found"
  | "not_found"
  | "unsupported"
  | "rate_limited"
  | "deferred";

/** Reusable signature block. */
export interface DiscoverySignature {
  algorithm: string;
  key_id: string;
  value: string;
}

/** SEMP_DISCOVERY request body per §4.1. */
export interface DiscoveryRequest {
  type: typeof DiscoveryMessageType;
  step: typeof DiscoveryStepRequest;
  version: string;
  id: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  addresses: string[];
  extensions?: Record<string, unknown>;
}

/** One entry in a {@link DiscoveryResponse}. */
export interface DiscoveryResult {
  address: string;
  status: DiscoveryStatus;
  transports?: string[];
  suites?: string[];
  server?: string;
  /** Cache TTL in seconds. */
  ttl: number;
}

/** SEMP_DISCOVERY response body per §4.3. */
export interface DiscoveryResponse {
  type: typeof DiscoveryMessageType;
  step: typeof DiscoveryStepResponse;
  version: string;
  id: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  results: DiscoveryResult[];
  signature: DiscoverySignature;
  extensions?: Record<string, unknown>;
}

/** Sign a {@link DiscoveryResponse} under the answering domain's signing key. */
export function signDiscoveryResponse(
  resp: DiscoveryResponse,
  domainPriv: Uint8Array,
  domainKeyId: string,
): string {
  if (domainKeyId === "") {
    throw new Error("discovery: empty domain key_id");
  }
  validateDiscoveryResponse(resp, { skipSignatureCheck: true });
  resp.signature.algorithm = "ed25519";
  resp.signature.key_id = domainKeyId;
  resp.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: resp as unknown as Record<string, unknown>,
    seed: domainPriv,
    signaturePath: "signature.value",
    prefix: DiscoverySignaturePrefix,
  });
  resp.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify a {@link DiscoveryResponse} under the answering domain's public key. */
export function verifyDiscoveryResponse(
  resp: DiscoveryResponse,
  domainPub: Uint8Array,
): boolean {
  validateDiscoveryResponse(resp);
  if (resp.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: resp as unknown as Record<string, unknown>,
    publicKey: domainPub,
    signaturePath: "signature.value",
    prefix: DiscoverySignaturePrefix,
  });
  return ok;
}

/** Structural validation of a {@link DiscoveryRequest}. Throws on first violation. */
export function validateDiscoveryRequest(req: DiscoveryRequest): void {
  if (req.type !== DiscoveryMessageType) {
    throw new Error(
      `discovery: request type ${JSON.stringify(req.type)}, want ${DiscoveryMessageType}`,
    );
  }
  if (req.step !== DiscoveryStepRequest) {
    throw new Error(
      `discovery: request step ${JSON.stringify(req.step)}, want ${DiscoveryStepRequest}`,
    );
  }
  for (const f of ["version", "id", "timestamp"] as const) {
    if (typeof req[f] !== "string" || req[f] === "") {
      throw new Error(`discovery: request missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(req.timestamp))) {
    throw new Error("discovery: request timestamp is not ISO 8601");
  }
  if (!Array.isArray(req.addresses) || req.addresses.length === 0) {
    throw new Error("discovery: request addresses must be a non-empty array");
  }
  for (let i = 0; i < req.addresses.length; i++) {
    if (typeof req.addresses[i] !== "string" || req.addresses[i] === "") {
      throw new Error(`discovery: request addresses[${i}] missing`);
    }
  }
}

/** Structural validation of a {@link DiscoveryResponse}. Throws on first violation. */
export function validateDiscoveryResponse(
  resp: DiscoveryResponse,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (resp.type !== DiscoveryMessageType) {
    throw new Error(
      `discovery: response type ${JSON.stringify(resp.type)}, want ${DiscoveryMessageType}`,
    );
  }
  if (resp.step !== DiscoveryStepResponse) {
    throw new Error(
      `discovery: response step ${JSON.stringify(resp.step)}, want ${DiscoveryStepResponse}`,
    );
  }
  for (const f of ["version", "id", "timestamp"] as const) {
    if (typeof resp[f] !== "string" || resp[f] === "") {
      throw new Error(`discovery: response missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(resp.timestamp))) {
    throw new Error("discovery: response timestamp is not ISO 8601");
  }
  if (!Array.isArray(resp.results)) {
    throw new Error("discovery: response results must be an array");
  }
  for (let i = 0; i < resp.results.length; i++) {
    const r = resp.results[i]!;
    if (typeof r.address !== "string" || r.address === "") {
      throw new Error(`discovery: response results[${i}] missing address`);
    }
    if (
      r.status !== "found" &&
      r.status !== "not_found" &&
      r.status !== "unsupported" &&
      r.status !== "rate_limited" &&
      r.status !== "deferred"
    ) {
      throw new Error(
        `discovery: response results[${i}] status ${JSON.stringify(r.status)} is invalid`,
      );
    }
    if (!Number.isInteger(r.ttl) || r.ttl < 0) {
      throw new Error(`discovery: response results[${i}] ttl ${r.ttl} MUST be >= 0`);
    }
  }
  if (typeof resp.signature?.value !== "string") {
    throw new Error("discovery: response signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && resp.signature.value === "") {
    throw new Error("discovery: response is unsigned");
  }
}
