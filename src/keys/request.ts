/**
 * SEMP_KEYS request / response per CLIENT.md §5.4 + KEY.md §4.
 *
 * Clients send a SEMP_KEYS request over their authenticated session
 * to ask the home server for one or more recipient users' published
 * keys. The home server fulfills the request from cache or by
 * fetching from the remote domain's well-known URI / federation
 * session and returns a SEMP_KEYS response.
 *
 * @module
 */

/** Wire-level type discriminator. */
export const KeysRequestType = "SEMP_KEYS";

/** Wire-level version per ENVELOPE.md §1.4. */
export const KeysRequestVersion = "1.0.0";

/** Step discriminator for SEMP_KEYS messages. */
export type KeysRequestStep = "request" | "response";

/** Per-address lookup status per CLIENT.md §5.4.5. */
export type KeysResultStatus = "found" | "not_found" | "error";

/** A single key record per KEY.md §3 / §10.6. */
export interface KeyRecord {
  algorithm: string;
  /** Base64-encoded public key. */
  public_key: string;
  /** Lowercase-hex SHA-256 fingerprint. */
  key_id: string;
  /** Key kind: "identity" | "encryption". */
  key_type?: string;
  /** Address the key belongs to (for user-key records). */
  address?: string;
  /** ISO 8601 UTC. */
  created?: string;
  /** ISO 8601 UTC; absent for non-expiring keys. */
  expires?: string;
  /** Per-key revocation block when the key has been revoked. */
  revocation?: {
    reason: string;
    /** ISO 8601 UTC. */
    revoked_at: string;
    /** Optional successor key fingerprint. */
    replacement_key_id?: string;
  };
}

/** Reusable signature block. */
export interface KeysSignatureBlock {
  algorithm: string;
  key_id: string;
  /** Base64. */
  value: string;
}

/** SEMP_KEYS request schema per §5.4.1. */
export interface KeysRequest {
  type: typeof KeysRequestType;
  step: "request";
  version: string;
  /** ULID for the request - used to correlate the response. */
  id: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  addresses: string[];
  /** Default `true`. When false, the response omits domain key records. */
  include_domain_keys: boolean;
}

/** SEMP_KEYS response schema per §5.4.3. */
export interface KeysResponse {
  type: typeof KeysRequestType;
  step: "response";
  version: string;
  /** Echo of the originating request id. */
  id: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  results: KeysResponseResult[];
}

/** One entry in a {@link KeysResponse} per §5.4.5. */
export interface KeysResponseResult {
  address: string;
  status: KeysResultStatus;
  /** Recipient's domain (suffix of `address` after `@`). */
  domain: string;
  /** Domain signing key record (when `include_domain_keys === true`). */
  domain_key?: KeyRecord;
  /** Domain encryption key record (when `include_domain_keys === true`). */
  domain_enc_key?: KeyRecord;
  /** Per-user key set. Always present (possibly empty) on `status === "found"`. */
  user_keys: KeyRecord[];
  /** Remote domain's signature over the key material per §5.4.5. */
  origin_signature?: KeysSignatureBlock;
  /** Human-readable diagnostic; populated only on `status === "error"`. */
  error_reason?: string;
}

/**
 * Construct a SEMP_KEYS request with `version` + `timestamp`
 * pre-populated and `include_domain_keys` set to the spec default
 * (true).
 */
export function newKeysRequest(
  id: string,
  addresses: string[],
  nowFn: () => Date = () => new Date(),
): KeysRequest {
  if (id === "") {
    throw new Error("keys: empty request id");
  }
  if (addresses.length === 0) {
    throw new Error("keys: request requires at least one address");
  }
  return {
    type: KeysRequestType,
    step: "request",
    version: KeysRequestVersion,
    id,
    timestamp: isoSecond(nowFn()),
    addresses,
    include_domain_keys: true,
  };
}

/** Construct a SEMP_KEYS response echoing `requestId`. */
export function newKeysResponse(
  requestId: string,
  results: KeysResponseResult[],
  nowFn: () => Date = () => new Date(),
): KeysResponse {
  if (requestId === "") {
    throw new Error("keys: empty request id");
  }
  return {
    type: KeysRequestType,
    step: "response",
    version: KeysRequestVersion,
    id: requestId,
    timestamp: isoSecond(nowFn()),
    results,
  };
}

/**
 * Validate a SEMP_KEYS request structurally per §5.4.1. Throws on
 * the first violation.
 */
export function validateKeysRequest(req: KeysRequest): void {
  if (req.type !== KeysRequestType) {
    throw new Error(`keys: type ${JSON.stringify(req.type)}, want ${KeysRequestType}`);
  }
  if (req.step !== "request") {
    throw new Error(`keys: step ${JSON.stringify(req.step)}, want "request"`);
  }
  if (typeof req.version !== "string" || req.version === "") {
    throw new Error("keys: missing version");
  }
  if (typeof req.id !== "string" || req.id === "") {
    throw new Error("keys: missing id");
  }
  if (typeof req.timestamp !== "string" || req.timestamp === "") {
    throw new Error("keys: missing timestamp");
  }
  if (Number.isNaN(Date.parse(req.timestamp))) {
    throw new Error("keys: timestamp is not ISO 8601");
  }
  if (!Array.isArray(req.addresses) || req.addresses.length === 0) {
    throw new Error("keys: addresses must be a non-empty array");
  }
  for (let i = 0; i < req.addresses.length; i++) {
    if (typeof req.addresses[i] !== "string" || req.addresses[i] === "") {
      throw new Error(`keys: addresses[${i}] missing`);
    }
  }
  if (typeof req.include_domain_keys !== "boolean") {
    throw new Error("keys: include_domain_keys must be a boolean");
  }
}

/**
 * Minimal stream interface a {@link KeysFetcher} consumes. Both the
 * h2 client's turn-based Conn and an in-memory channel pair satisfy
 * this shape.
 */
export interface KeysClientStream {
  send(message: Uint8Array): Promise<void>;
  receive(): Promise<Uint8Array | null>;
}

/**
 * Send a SEMP_KEYS request on the supplied stream and parse the
 * response. The home server is expected to fulfill the request
 * synchronously and respond on the same stream.
 *
 * Returns the parsed {@link KeysResponse}. Throws on transport
 * failure, malformed JSON, response that is not a SEMP_KEYS
 * response, or response whose `id` does not match the request.
 */
export async function fetchKeys(
  stream: KeysClientStream,
  req: KeysRequest,
): Promise<KeysResponse> {
  validateKeysRequest(req);
  await stream.send(new TextEncoder().encode(JSON.stringify(req)));
  const respBytes = await stream.receive();
  if (respBytes === null) {
    throw new Error("keys: connection closed waiting for response");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(respBytes));
  } catch (err) {
    throw new Error(
      `keys: response parse: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed)
  ) {
    throw new Error("keys: response is not a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.type !== KeysRequestType) {
    throw new Error(
      `keys: response type ${JSON.stringify(obj.type)}, want ${KeysRequestType}`,
    );
  }
  if (obj.step !== "response") {
    throw new Error(
      `keys: response step ${JSON.stringify(obj.step)}, want "response"`,
    );
  }
  if (obj.id !== req.id) {
    throw new Error(
      `keys: response id ${JSON.stringify(obj.id)} does not match request ${JSON.stringify(req.id)}`,
    );
  }
  return obj as unknown as KeysResponse;
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
