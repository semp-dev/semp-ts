/**
 * Handshake abort + rejection helpers per HANDSHAKE.md §2.2a.6 + §4.
 *
 * - {@link ChallengeInvalidError}: error type a client raises when a
 *   received challenge violates §2.2a.3 binding rules. Drivers catch
 *   it and emit a `challenge_invalid` rejection.
 * - {@link buildClientRejection}: produce an unsigned client-side
 *   rejection message (party=client). The client has not authenticated
 *   to the server at this point, so the wire form has no
 *   `server_signature` and uses canonical bytes directly.
 * - {@link isResumptionFailed}: classifies a `HandshakeRejectedError`
 *   as a recoverable resumption failure that callers should fall back
 *   from to a full handshake.
 *
 * @module
 */

import { marshal as canonicalMarshal } from "../canonical/index.js";

import { HandshakeRejectedError } from "./driver.js";
import { HandshakeVersion } from "./messages.js";

/**
 * Error a client raises when a received challenge violates §2.2a.3
 * binding rules. The handshake driver catches this, sends a
 * `challenge_invalid` rejection, then re-raises to the caller.
 */
export class ChallengeInvalidError extends Error {
  override readonly name = "ChallengeInvalidError";
  /** Detail emitted verbatim in the abort message's `reason` field. */
  readonly detail: string;

  constructor(detail: string) {
    super(`handshake: challenge_invalid: ${detail}`);
    this.detail = detail;
  }
}

/** Type guard for {@link ChallengeInvalidError}. */
export function isChallengeInvalid(err: unknown): err is ChallengeInvalidError {
  return err instanceof ChallengeInvalidError;
}

/**
 * Build an unsigned client-initiator abort message per §2.2a.6.
 *
 * The wire shape is `party: "client"` with no `server_signature` —
 * the initiator has not authenticated to the server at this point
 * and MUST NOT do so as part of an abort.
 *
 * Returns canonical UTF-8 JSON bytes ready to send on the handshake
 * stream. The caller closes the transport after sending.
 */
export function buildClientRejection(
  reasonCode: string,
  reason?: string,
): Uint8Array {
  if (reasonCode === "") {
    throw new Error("handshake: empty reason_code in client rejection");
  }
  const msg: Record<string, unknown> = {
    type: "SEMP_HANDSHAKE",
    step: "rejected",
    party: "client",
    version: HandshakeVersion,
    reason_code: reasonCode,
    reason: reason ?? "",
    extensions: {},
  };
  return canonicalMarshal(msg);
}

/** Reason codes per HANDSHAKE.md §2.8 that the spec treats as recoverable resumption failures. */
const RECOVERABLE_RESUMPTION_REASONS: ReadonlySet<string> = new Set([
  "resumption_failed",
  "session_expired",
  "no_session",
]);

/**
 * Report whether `err` is a {@link HandshakeRejectedError} whose
 * reason code indicates the resume attempt failed in a way the
 * client should retry as a full handshake. Per HANDSHAKE.md §2.8:
 * if the server has lost session state or the ticket has expired,
 * the client falls back to a fresh handshake.
 */
export function isResumptionFailed(err: unknown): boolean {
  if (!(err instanceof HandshakeRejectedError)) {
    return false;
  }
  return RECOVERABLE_RESUMPTION_REASONS.has(err.reasonCode);
}
