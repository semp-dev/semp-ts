/**
 * Wire serialization helpers per ENVELOPE.md §2.1 + MIME.md §2.2.
 *
 * `encodeEnvelope` produces the on-the-wire UTF-8 JSON. The output is
 * suitable for transmission over any SEMP transport
 * (`Content-Type: application/semp-envelope`) and for storage as a
 * `.semp` file.
 *
 * `encodeEnvelope` does NOT produce the canonical form — use
 * {@link "./canonical".canonicalEnvelopeBytes} for the byte stream
 * consumed by signature and MAC computation.
 *
 * @module
 */

import type { Envelope } from "./compose.js";

/** SEMP wire MIME type per MIME.md §2.2. */
export const EnvelopeMIMEType = "application/semp-envelope";

/** SEMP envelope file extension per MIME.md §2.2. */
export const EnvelopeFileExtension = ".semp";

/**
 * Wire JSON serialization of `env`. UTF-8, no BOM, no trailing
 * newline — the byte sequence is suitable for transport bodies and
 * for direct `.semp` file content.
 */
export function encodeEnvelope(env: Envelope): Uint8Array {
  // Plain JSON — NOT canonical. Used for transport, not signing.
  return new TextEncoder().encode(JSON.stringify(env));
}

/**
 * Alias for {@link encodeEnvelope} that names the `.semp` file
 * use case explicitly. MIME.md §2.2 specifies one envelope per file;
 * this helper enforces that contract by returning the same single-
 * envelope JSON.
 */
export function encodeEnvelopeFile(env: Envelope): Uint8Array {
  return encodeEnvelope(env);
}

/**
 * Parse a SEMP envelope from wire bytes. Throws on malformed JSON
 * or when the parsed value is missing the discriminator
 * `type === "SEMP_ENVELOPE"`.
 */
export function decodeEnvelope(data: Uint8Array | string): Envelope {
  const text = typeof data === "string" ? data : new TextDecoder().decode(data);
  if (text === "") {
    throw new Error("envelope: empty input");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(
      `envelope: parse: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed)
  ) {
    throw new Error("envelope: top-level value is not an object");
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.type !== "SEMP_ENVELOPE") {
    throw new Error(
      `envelope: type ${JSON.stringify(obj.type)} is not SEMP_ENVELOPE`,
    );
  }
  return obj as unknown as Envelope;
}

/** Decode a `.semp` file body. Mirrors {@link decodeEnvelope}. */
export function decodeEnvelopeFile(data: Uint8Array | string): Envelope {
  return decodeEnvelope(data);
}
