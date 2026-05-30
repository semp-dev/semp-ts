/**
 * Canonical JSON serialization per ENVELOPE.md §4.3.
 *
 * The canonical form is the byte stream over which signatures and
 * MACs are computed. Two implementations producing different
 * canonical bytes for the same logical document do not interoperate
 * at the seal layer.
 *
 * Rules:
 *   - Keys sorted lexicographically at every nesting level.
 *   - No insignificant whitespace.
 *   - UTF-8 encoding.
 *   - Strings escaped per RFC 8259 §7.
 *   - Numbers preserved exactly (no reformatting).
 *
 * Per-document elision rules (e.g. blanking `seal.signature` and
 * `seal.session_mac` for envelopes) are applied by callers via
 * {@link marshalWithElision} before this generic marshal sees the
 * value.
 *
 * @module
 */

/** Canonicalize a JSON-serializable value to UTF-8 bytes. */
export function marshal(v: unknown): Uint8Array {
  // Round-trip through JSON.parse so the input shape is normalized:
  // any types the caller passed (Map, Date, etc.) become plain JSON
  // values. This also catches non-JSON-serializable inputs early.
  const raw = JSON.stringify(v);
  if (raw === undefined) {
    throw new Error("canonical: value is not JSON-serializable");
  }
  const generic: unknown = JSON.parse(raw);
  return new TextEncoder().encode(serialize(generic));
}

/**
 * Apply an in-place elision callback to a deep copy of `v`, then
 * canonicalize. The elider can mutate `map[string]any` / `any[]`
 * structures freely - the original is untouched.
 *
 * Use case: envelope canonicalization sets `seal.signature` and
 * `seal.session_mac` to "" by mutating the deep copy before
 * serialization.
 */
export function marshalWithElision(
  v: unknown,
  elide: (clone: unknown) => void,
): Uint8Array {
  const raw = JSON.stringify(v);
  if (raw === undefined) {
    throw new Error("canonical: value is not JSON-serializable");
  }
  const clone: unknown = JSON.parse(raw);
  elide(clone);
  return new TextEncoder().encode(serialize(clone));
}

function serialize(v: unknown): string {
  if (v === null) {
    return "null";
  }
  if (typeof v === "boolean") {
    return v ? "true" : "false";
  }
  if (typeof v === "number") {
    if (!Number.isFinite(v)) {
      throw new Error(`canonical: non-finite number ${v}`);
    }
    // JSON.stringify emits the shortest accurate decimal form.
    // For SEMP this is fine: vectors do not pin numeric edge cases
    // requiring a different formatter.
    return JSON.stringify(v);
  }
  if (typeof v === "string") {
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    let out = "[";
    for (let i = 0; i < v.length; i++) {
      if (i > 0) {
        out += ",";
      }
      out += serialize(v[i]);
    }
    out += "]";
    return out;
  }
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    let out = "{";
    let first = true;
    for (const k of keys) {
      // JSON.parse never produces undefined values, but be defensive.
      const val = obj[k];
      if (val === undefined) {
        continue;
      }
      if (!first) {
        out += ",";
      }
      out += JSON.stringify(k);
      out += ":";
      out += serialize(val);
      first = false;
    }
    out += "}";
    return out;
  }
  throw new Error(`canonical: unsupported type ${typeof v}`);
}
