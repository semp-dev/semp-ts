/**
 * Confirmation hash per HANDSHAKE.md §2.5.3.
 *
 * The hash binds the client's identity proof to the specific
 * handshake exchange it was issued in. Both parties compute the same
 * hash from the canonical bytes of message_1 (init) and message_2
 * (response).
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Compute SHA-256 over the concatenation of canonical(message_1)
 * and canonical(message_2). The caller MUST pass the canonical
 * bytes — sorted keys, no insignificant whitespace, as defined in
 * ENVELOPE.md §4.3 — not the wire-format bytes.
 *
 * The output is the 32-byte digest the client signs as part of its
 * identity proof.
 */
export function confirmationHash(
  message1Canonical: Uint8Array,
  message2Canonical: Uint8Array,
): Uint8Array {
  const buf = new Uint8Array(message1Canonical.length + message2Canonical.length);
  buf.set(message1Canonical, 0);
  buf.set(message2Canonical, message1Canonical.length);
  return sha256(buf);
}
