/**
 * Discovery resolver - well-known URI fetch + parse, plus the
 * higher-level "resolve a server" orchestrator that produces the
 * `serverDomainPub` a {@link "../handshake/driver".runClient} call
 * needs.
 *
 * The resolver is fetch-injectable so tests can stub the HTTPS
 * round-trips; production callers omit the `fetchImpl` option and
 * the resolver uses Node 22+'s global `fetch`.
 *
 * The DNS SRV / TXT lookup leg of §5.1 is intentionally not
 * implemented in this module - it requires `node:dns/promises` and
 * does not cleanly tree-shake into a browser bundle. Callers that
 * need DNS-first discovery wire it in front of {@link resolveServer}
 * and pass an explicit `host` / well-known URL.
 *
 * @module
 */

import {
  type Configuration,
  WellKnownMaxBytes,
  WellKnownPath,
  parseConfiguration,
} from "./configuration.js";
import {
  type DomainKeys,
  type KeyBlock,
  DomainKeysMaxBytes,
  decodeKeyBlockPublic,
  parseDomainKeys,
  verifyDomainKeyFingerprint,
} from "./domain_keys.js";

/**
 * Minimal subset of the WHATWG fetch surface this module depends on.
 * Both Node 22+ and browsers ship `fetch` matching this shape. Tests
 * pass a fake to drive deterministic responses.
 */
export type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<{
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}>;

/** Options shared by every fetch in this module. */
export interface FetchOptions {
  /** Override the fetch implementation. Defaults to `globalThis.fetch`. */
  fetchImpl?: FetchLike;
  /** Optional cancellation signal. */
  signal?: AbortSignal;
  /**
   * Per-request timeout in milliseconds. Defaults to 10 seconds -
   * matches semp-go's `FetchConfiguration` default.
   */
  timeoutMs?: number;
}

/** Build the canonical well-known URL for a given hostname. */
export function wellKnownUrl(host: string): string {
  if (host === "") {
    throw new Error("discovery: empty host");
  }
  return `https://${host}${WellKnownPath}`;
}

/**
 * GET the well-known configuration document and return it parsed.
 * Throws on transport failure, non-200 status, oversized body, or
 * structural parse failure.
 *
 * The URL's scheme is NOT enforced - production callers must pass an
 * `https://` URL, but tests need to point at a local httptest-style
 * server so this layer stays permissive.
 */
export async function fetchConfiguration(
  url: string,
  opts: FetchOptions = {},
): Promise<Configuration> {
  const body = await fetchTextBounded(url, WellKnownMaxBytes, opts);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(
      `discovery: configuration parse: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return parseConfiguration(parsed);
}

/**
 * GET the domain-keys document at the URL advertised as
 * `endpoints.domain_keys` in a server's configuration. Returns the
 * parsed document and the cross-checked signing-key public bytes.
 *
 * Throws if the fingerprint cross-check fails - a peer that trusts
 * the publication channel still MUST confirm `key_id` is the SHA-256
 * fingerprint of `public_key`, otherwise a misconfiguration could
 * swap in a key whose fingerprint doesn't match the one the peer
 * cached.
 */
export async function fetchDomainKeys(
  url: string,
  opts: FetchOptions = {},
): Promise<{ domainKeys: DomainKeys; signingPub: Uint8Array; encryptionPub: Uint8Array }> {
  const body = await fetchTextBounded(url, DomainKeysMaxBytes, opts);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(
      `discovery: domain_keys parse: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const domainKeys = parseDomainKeys(parsed);

  if (!verifyDomainKeyFingerprint(domainKeys.signing_key)) {
    throw new Error(
      "discovery: domain_keys.signing_key.key_id does not match SHA-256(public_key)",
    );
  }
  if (!verifyDomainKeyFingerprint(domainKeys.encryption_key)) {
    throw new Error(
      "discovery: domain_keys.encryption_key.key_id does not match SHA-256(public_key)",
    );
  }

  return {
    domainKeys,
    signingPub: decodeKeyBlockPublic(domainKeys.signing_key),
    encryptionPub: decodeKeyBlockPublic(domainKeys.encryption_key),
  };
}

/** Result of {@link resolveServer}. */
export interface ResolvedServer {
  /** The full configuration document. */
  configuration: Configuration;
  /** Parsed domain-keys document. */
  domainKeys: DomainKeys;
  /** 32-byte Ed25519 domain signing public key. */
  signingPub: Uint8Array;
  /** Lowercase-hex SHA-256 fingerprint of `signingPub`. */
  signingKeyId: string;
  /** 32-byte X25519 domain encryption public key. */
  encryptionPub: Uint8Array;
  /** Lowercase-hex SHA-256 fingerprint of `encryptionPub`. */
  encryptionKeyId: string;
}

/** Inputs to {@link resolveServer}. */
export interface ResolveServerOptions extends FetchOptions {
  /**
   * Override the configuration URL. When omitted, the resolver uses
   * `https://<domain>/.well-known/semp/configuration` per §3 / §5.5.
   * Callers that have already done DNS SRV discovery pass the SRV
   * target host instead.
   */
  configurationUrl?: string;
}

/**
 * High-level resolver: fetch the configuration, then fetch the
 * domain-keys at `endpoints.domain_keys`, then return the structured
 * result. The `signingPub` field is what
 * {@link "../handshake/driver".runClient} needs as its
 * `serverDomainPub` config.
 */
export async function resolveServer(
  domain: string,
  opts: ResolveServerOptions = {},
): Promise<ResolvedServer> {
  if (domain === "") {
    throw new Error("discovery: empty domain");
  }
  const configUrl = opts.configurationUrl ?? wellKnownUrl(domain);
  const configuration = await fetchConfiguration(configUrl, opts);

  const domainKeysUrl = configuration.endpoints.domain_keys;
  if (typeof domainKeysUrl !== "string" || domainKeysUrl === "") {
    throw new Error("discovery: configuration missing endpoints.domain_keys");
  }
  const { domainKeys, signingPub, encryptionPub } = await fetchDomainKeys(
    domainKeysUrl,
    opts,
  );

  return {
    configuration,
    domainKeys,
    signingPub,
    signingKeyId: domainKeys.signing_key.key_id,
    encryptionPub,
    encryptionKeyId: domainKeys.encryption_key.key_id,
  };
}

// ---------------------------------------------------------------------------
// HTTP plumbing

async function fetchTextBounded(
  url: string,
  maxBytes: number,
  opts: FetchOptions,
): Promise<string> {
  if (url === "") {
    throw new Error("discovery: empty URL");
  }
  const fetchImpl = opts.fetchImpl ?? defaultFetch();

  // Compose a timeout-aware abort signal. The runtime supports
  // AbortSignal.timeout when present; otherwise we wire it manually.
  const externalSignal = opts.signal;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const timeoutController = new AbortController();
  const timer = setTimeout(() => timeoutController.abort(), timeoutMs);
  const externalListener = () => timeoutController.abort();
  if (externalSignal !== undefined) {
    if (externalSignal.aborted) {
      timeoutController.abort();
    } else {
      externalSignal.addEventListener("abort", externalListener, { once: true });
    }
  }

  let resp;
  try {
    resp = await fetchImpl(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: timeoutController.signal,
    });
  } finally {
    clearTimeout(timer);
    if (externalSignal !== undefined) {
      externalSignal.removeEventListener("abort", externalListener);
    }
  }

  if (!resp.ok) {
    throw new Error(`discovery: GET ${url} returned ${resp.status}`);
  }

  // Permissive content-type check - some servers return
  // application/octet-stream for .json paths. We require JSON in the
  // body parse, not in the header.
  const ct = resp.headers.get("content-type") ?? "";
  if (
    ct !== "" &&
    !ct.toLowerCase().includes("json") &&
    !ct.toLowerCase().includes("octet-stream")
  ) {
    throw new Error(`discovery: GET ${url}: unexpected content-type ${ct}`);
  }

  const body = await resp.text();
  // Use UTF-8 byte length; JS strings are UTF-16 internally but the
  // wire-side cap is in bytes. Buffer.byteLength is constant-time.
  const byteLen =
    typeof Buffer !== "undefined"
      ? Buffer.byteLength(body, "utf8")
      : new TextEncoder().encode(body).length;
  if (byteLen > maxBytes) {
    throw new Error(
      `discovery: GET ${url}: body exceeds ${maxBytes} bytes (got ${byteLen})`,
    );
  }
  return body;
}

function defaultFetch(): FetchLike {
  const f = (globalThis as unknown as { fetch?: FetchLike }).fetch;
  if (f === undefined) {
    throw new Error(
      "discovery: globalThis.fetch is undefined. Pass a fetchImpl option, or run on Node 22+ / a browser.",
    );
  }
  return f;
}

// Re-export helpers for callers that prefer the lower-level pieces.
export { decodeKeyBlockPublic, verifyDomainKeyFingerprint };
export type { Configuration, DomainKeys, KeyBlock };
