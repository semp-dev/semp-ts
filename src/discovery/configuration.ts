/**
 * Well-known configuration document parsing per DISCOVERY.md §3.1.
 *
 * The bootstrapping path `/.well-known/semp/configuration` returns a
 * JSON document that describes a server's capabilities, transport
 * endpoints, API endpoints, and supported extensions. This module
 * provides a typed shape and a validator that enforces the §3.2
 * "fixed by the protocol" rules:
 *
 *  - `type` MUST be `"SEMP_CONFIGURATION"`
 *  - `endpoints.client` and `endpoints.federation` MUST each contain
 *    at least an `h2` entry
 *  - `endpoints.register`, `endpoints.keys`, `endpoints.domain_keys`
 *    MUST be present
 *  - `suites` MUST contain at least `x25519-chacha20-poly1305`
 *  - `limits.max_envelope_size` MUST be present
 *
 * Unknown fields are preserved on the typed object via the
 * index signature so callers can read forward-compatible additions
 * without requiring a parser update.
 *
 * @module
 */

/** Canonical well-known path. Fixed by the protocol per §3. */
export const WellKnownPath = "/.well-known/semp/configuration";

/** Document `type` discriminator. */
export const ConfigurationType = "SEMP_CONFIGURATION";

/**
 * Maximum byte size accepted for a fetched well-known body. 64 KiB
 * is large enough for any reasonable configuration (including rich
 * extension maps) without letting a hostile server feed us
 * gigabytes.
 */
export const WellKnownMaxBytes = 64 * 1024;

/** Endpoint group: transport-identifier → URL. */
export type TransportEndpoints = Record<string, string>;

/** Endpoints object per §3.1.1. */
export interface ConfigEndpoints {
  client: TransportEndpoints;
  federation: TransportEndpoints;
  register: string;
  device_register?: string;
  blocklist?: string;
  keys: string;
  domain_keys: string;
  reputation?: string;
  reputation_references?: string;
  verify?: string;
  reputation_transfer?: string;
  backup?: string;
  migration?: string;
  transparency_log?: string;
  attachment_storage?: string;
  /** Forward-compatible: any unknown endpoint URL keys land here. */
  [key: string]: string | TransportEndpoints | undefined;
}

/** Operational limits per §3.1.3. */
export interface ConfigLimits {
  max_envelope_size: number;
  /** Future limits land here without requiring a parser update. */
  [key: string]: number | undefined;
}

/** Extension declaration per §3.1.4. */
export interface ConfigExtension {
  id: string;
  required: boolean;
}

/** Parsed well-known configuration document. */
export interface Configuration {
  type: typeof ConfigurationType;
  version: string;
  domain: string;
  revision: number;
  ttl_seconds: number;
  endpoints: ConfigEndpoints;
  suites: string[];
  limits: ConfigLimits;
  extensions?: ConfigExtension[];
  /** Forward-compatible: unknown top-level fields preserved here. */
  [key: string]: unknown;
}

/**
 * Validate and narrow a parsed JSON value into a {@link Configuration}.
 * Throws with a descriptive message on the first protocol violation.
 *
 * The validator enforces the §3.2 mandatory-fixed rules (h2 baseline,
 * x25519 baseline, max_envelope_size present) but is permissive about
 * unknown fields per §3.1 ("Implementations MUST ignore unknown
 * fields rather than failing").
 */
export function parseConfiguration(value: unknown): Configuration {
  if (!isRecord(value)) {
    throw new Error("configuration: not a JSON object");
  }
  if (value.type !== ConfigurationType) {
    throw new Error(
      `configuration: type ${JSON.stringify(value.type)}, want ${ConfigurationType}`,
    );
  }
  requireString(value, "version");
  requireString(value, "domain");
  requireInt(value, "revision");
  requireInt(value, "ttl_seconds");

  const endpoints = requireObject(value, "endpoints");
  const client = requireTransportMap(endpoints, "endpoints.client");
  const federation = requireTransportMap(endpoints, "endpoints.federation");
  if (typeof client.h2 !== "string" || client.h2 === "") {
    throw new Error("configuration: endpoints.client.h2 missing (mandatory baseline)");
  }
  if (typeof federation.h2 !== "string" || federation.h2 === "") {
    throw new Error("configuration: endpoints.federation.h2 missing (mandatory baseline)");
  }
  requireString(endpoints, "register");
  requireString(endpoints, "keys");
  requireString(endpoints, "domain_keys");

  const suites = requireStringArray(value, "suites");
  if (!suites.includes("x25519-chacha20-poly1305")) {
    throw new Error(
      "configuration: suites missing x25519-chacha20-poly1305 (mandatory baseline)",
    );
  }

  const limits = requireObject(value, "limits");
  requireInt(limits, "max_envelope_size");

  // Extensions optional per §3.1.4.
  if (value.extensions !== undefined) {
    if (!Array.isArray(value.extensions)) {
      throw new Error("configuration: extensions: not an array");
    }
    for (let i = 0; i < value.extensions.length; i++) {
      const ext = value.extensions[i];
      if (!isRecord(ext)) {
        throw new Error(`configuration: extensions[${i}]: not an object`);
      }
      if (typeof ext.id !== "string" || ext.id === "") {
        throw new Error(`configuration: extensions[${i}].id missing`);
      }
      if (typeof ext.required !== "boolean") {
        throw new Error(`configuration: extensions[${i}].required must be boolean`);
      }
    }
  }

  return value as unknown as Configuration;
}

// ---------------------------------------------------------------------------
// Tiny type-narrowing helpers shared with domain_keys.ts.

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v === "") {
    throw new Error(`configuration: ${key}: missing or not a non-empty string`);
  }
  return v;
}

export function requireInt(obj: Record<string, unknown>, key: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error(`configuration: ${key}: missing or not an integer`);
  }
  return v;
}

export function requireObject(
  obj: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const v = obj[key];
  if (!isRecord(v)) {
    throw new Error(`configuration: ${key}: missing or not an object`);
  }
  return v;
}

export function requireStringArray(
  obj: Record<string, unknown>,
  key: string,
): string[] {
  const v = obj[key];
  if (!Array.isArray(v)) {
    throw new Error(`configuration: ${key}: missing or not an array`);
  }
  for (let i = 0; i < v.length; i++) {
    if (typeof v[i] !== "string") {
      throw new Error(`configuration: ${key}[${i}]: not a string`);
    }
  }
  return v as string[];
}

function requireTransportMap(
  obj: Record<string, unknown>,
  key: string,
): TransportEndpoints {
  // The path here is a dotted key like "endpoints.client" but the
  // actual lookup is the leaf segment.
  const leaf = key.split(".").pop() ?? key;
  const v = obj[leaf];
  if (!isRecord(v)) {
    throw new Error(`configuration: ${key}: missing or not an object`);
  }
  for (const [k, val] of Object.entries(v)) {
    if (typeof val !== "string" || val === "") {
      throw new Error(`configuration: ${key}.${k}: not a non-empty string`);
    }
  }
  return v as TransportEndpoints;
}
