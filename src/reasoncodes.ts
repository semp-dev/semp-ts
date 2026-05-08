/**
 * Reason-code registry per VECTORS.md §8 / HANDSHAKE.md §4.1 /
 * ENVELOPE.md §9.3 / ERRORS.md.
 *
 * @module
 */

/**
 * Machine-readable rejection reason returned by handshake,
 * envelope, key-fetch, and policy operations. Senders use the
 * code to decide whether to retry, surface to user, or rotate
 * credentials.
 */
export type ReasonCode =
  // Handshake codes.
  | "blocked"
  | "auth_failed"
  | "policy_forbidden"
  | "handshake_expired"
  | "handshake_invalid"
  | "no_session"
  | "rate_limited"
  | "challenge"
  | "challenge_failed"
  | "challenge_invalid"
  | "server_at_capacity"
  | "resumption_failed"
  | "version_unsupported"
  // Envelope codes.
  | "seal_invalid"
  | "session_mac_invalid"
  | "envelope_expired"
  | "envelope_size_exceeded"
  | "extension_unsupported"
  | "extension_size_exceeded"
  | "scope_exceeded"
  | "scope_invalid"
  | "certificate_expired"
  | "server_unavailable"
  | "session_expired"
  | "rekey_unsupported"
  | "policy_kind_unsupported"
  | "policy_op_invalid"
  | "policy_version_stale";

/** The full set of recognized ReasonCode values. */
export const KnownReasonCodes: ReadonlySet<string> = new Set<ReasonCode>([
  "blocked",
  "auth_failed",
  "policy_forbidden",
  "handshake_expired",
  "handshake_invalid",
  "no_session",
  "rate_limited",
  "challenge",
  "challenge_failed",
  "challenge_invalid",
  "server_at_capacity",
  "resumption_failed",
  "version_unsupported",
  "seal_invalid",
  "session_mac_invalid",
  "envelope_expired",
  "envelope_size_exceeded",
  "extension_unsupported",
  "extension_size_exceeded",
  "scope_exceeded",
  "scope_invalid",
  "certificate_expired",
  "server_unavailable",
  "session_expired",
  "rekey_unsupported",
  "policy_kind_unsupported",
  "policy_op_invalid",
  "policy_version_stale",
]);

/** Type guard: is this string one of the recognized codes? */
export function isKnownReasonCode(code: string): code is ReasonCode {
  return KnownReasonCodes.has(code);
}

/**
 * Reports whether automated retry is appropriate for this reason.
 *
 * Recoverable codes signal a transient or transport condition the
 * sender SHOULD retry after a back-off, OR a state-staleness
 * condition (handshake_expired, no_session, policy_version_stale)
 * the sender resolves with a fresh handshake / refresh and a single
 * retry. Non-recoverable codes signal a permanent condition (blocked,
 * auth_failed, policy_forbidden, scope_invalid, etc.) where the
 * sender MUST NOT retry without operator intervention.
 *
 * Notes on edge cases:
 *
 *   - `session_expired` and `rekey_unsupported` are NOT recoverable
 *     here because they require a fresh handshake rather than an
 *     automated retry on the rekey path.
 *   - `challenge_invalid`, `version_unsupported`, `resumption_failed`,
 *     `envelope_size_exceeded`, `scope_invalid`, and
 *     `certificate_expired` are non-recoverable per ERRORS.md.
 *
 * Mirrors semp-go's `ReasonCode.Recoverable()` byte-for-byte; the
 * vectors at `vectors/v1.0.0/rejection-codes.json` cross-check both.
 */
export function isRecoverable(code: ReasonCode): boolean {
  switch (code) {
    case "handshake_expired":
    case "handshake_invalid":
    case "no_session":
    case "rate_limited":
    case "challenge":
    case "challenge_failed":
    case "server_at_capacity":
    case "policy_version_stale":
      return true;
    default:
      return false;
  }
}
