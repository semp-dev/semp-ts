/**
 * Extension validation per EXTENSIONS.md §2-§4.
 *
 * Each extension entry on the wire conforms to:
 *
 * ```json
 * { "required": false, "data": { ... } }
 * ```
 *
 * Per-layer byte-size ceilings (§4) are enforced before signature
 * verification - an over-large `extensions` map MUST be rejected
 * outright, regardless of any signature it might carry.
 *
 * Required extensions a recipient does not understand MUST be
 * rejected per §3, regardless of namespace. The semp.dev/ namespace
 * is reserved for spec-defined keys; vendor.* and x-* keys are at
 * the operator's own risk but are subject to the same
 * required-must-be-understood rule.
 *
 * @module
 */

/** Layers an `extensions` object can attach to. */
export type Layer = "postmark" | "seal" | "brief" | "enclosure";

/** A single extension entry on the wire. */
export interface Entry {
  required: boolean;
  data: unknown;
}

/** Wire-level container: keys are namespaced extension identifiers. */
export type Map = Record<string, Entry>;

/** Per-layer byte-size ceiling per §4.1. */
export function maxBytesFor(layer: Layer): number {
  switch (layer) {
    case "postmark":
      return 4096;
    case "seal":
      return 4096;
    case "brief":
      return 16_384;
    case "enclosure":
      return 65_536;
  }
}

/** Reserved namespace prefix for spec-defined extension keys. */
export const NamespacePrefixCore = "semp.dev/";

/** A registered extension. */
export interface RegistryEntry {
  identifier: string;
  layers: Layer[];
}

/**
 * Registry of known extensions an implementation supports. Used by
 * {@link validate} to decide whether a required extension is
 * understood (registered) or unknown (rejected).
 */
export class Registry {
  private readonly entries = new globalThis.Map<string, RegistryEntry>();

  register(entry: RegistryEntry): void {
    this.entries.set(entry.identifier, entry);
  }

  lookup(identifier: string): RegistryEntry | undefined {
    return this.entries.get(identifier);
  }
}

/** Error thrown when a required extension is not registered. */
export class UnsupportedError extends Error {
  readonly key: string;
  readonly layer: Layer;
  readonly reasonCode = "extension_unsupported" as const;
  constructor(key: string, layer: Layer) {
    super(
      `extensions: ${layer} layer required extension "${key}" is not supported`,
    );
    this.key = key;
    this.layer = layer;
  }
}

/** Error thrown when the serialized map exceeds the layer's ceiling. */
export class SizeError extends Error {
  readonly layer: Layer;
  readonly size: number;
  readonly limit: number;
  readonly reasonCode = "extension_size_exceeded" as const;
  constructor(layer: Layer, size: number, limit: number) {
    super(
      `extensions: ${layer} layer extensions object ${size} bytes exceeds limit ${limit}`,
    );
    this.layer = layer;
    this.size = size;
    this.limit = limit;
  }
}

/** Error thrown when an extension key fails {@link validateKey}. */
export class KeyError extends Error {
  readonly key: string;
  readonly layer: Layer;
  constructor(key: string, layer: Layer, reason: string) {
    super(`extensions: ${layer} layer key "${key}": ${reason}`);
    this.key = key;
    this.layer = layer;
  }
}

/** Maximum byte length of an extension key (the namespaced identifier). */
export const MaxKeyLength = 128;

/**
 * Validate an extension key per EXTENSIONS.md §2.2: ASCII only,
 * non-empty, MaxKeyLength cap, must contain a `/` after a vendor
 * namespace OR start with `x-` for experimental.
 */
export function validateKey(key: string): Error | null {
  if (key.length === 0) {
    return new Error("empty key");
  }
  if (key.length > MaxKeyLength) {
    return new Error(`key length ${key.length} exceeds ${MaxKeyLength}`);
  }
  for (let i = 0; i < key.length; i++) {
    const code = key.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) {
      return new Error(`non-printable-ASCII byte at offset ${i}`);
    }
  }
  if (!key.startsWith("x-") && !key.includes("/")) {
    return new Error("expected `<vendor>/<name>` or `x-<name>`");
  }
  return null;
}

/**
 * Validate an extensions map at a specific layer. Returns null on
 * accept; an Error on first reject.
 *
 * Rejects:
 *   - Malformed key shape ({@link KeyError})
 *   - Required extension not in registry, regardless of namespace
 *     ({@link UnsupportedError})
 *   - Required extension registered but for a different layer
 *     ({@link UnsupportedError})
 *   - Total serialized size over the layer's ceiling
 *     ({@link SizeError})
 *
 * Non-required (`required: false`) extensions are passed through
 * unconditionally - the receiver is free to ignore them.
 */
export function validate(
  registry: Registry | null,
  layer: Layer,
  m: Map | null | undefined,
): Error | null {
  if (m === null || m === undefined || Object.keys(m).length === 0) {
    return null;
  }
  const keys = Object.keys(m).sort();
  for (const k of keys) {
    const keyErr = validateKey(k);
    if (keyErr !== null) {
      return new KeyError(k, layer, keyErr.message);
    }
    const entry = m[k];
    if (entry === undefined || !entry.required) {
      continue;
    }
    if (registry === null) {
      // No registry == no extension knowledge. A required extension
      // is definitionally unsupported.
      return new UnsupportedError(k, layer);
    }
    const reg = registry.lookup(k);
    if (reg === undefined) {
      return new UnsupportedError(k, layer);
    }
    if (!reg.layers.includes(layer)) {
      return new UnsupportedError(k, layer);
    }
  }
  return validateSize(layer, m);
}

/**
 * Validate the serialized byte length of an extensions map against
 * the layer ceiling. Empty / missing maps pass through.
 */
export function validateSize(layer: Layer, m: Map | null | undefined): Error | null {
  if (m === null || m === undefined || Object.keys(m).length === 0) {
    return null;
  }
  const limit = maxBytesFor(layer);
  // Count UTF-8 byte length of the JSON serialization. The exact
  // canonical bytes are determined later by the seal computation;
  // for size-limit purposes plain JSON.stringify is within the same
  // order of magnitude (whitespace differences only).
  const serialized = JSON.stringify(m) ?? "";
  const bytes = new TextEncoder().encode(serialized).byteLength;
  if (bytes > limit) {
    return new SizeError(layer, bytes, limit);
  }
  return null;
}
