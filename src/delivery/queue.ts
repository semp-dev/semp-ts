/**
 * Per-recipient queue state record per DELIVERY.md §2.5.
 *
 * The sending server maintains one record per (envelope_id,
 * recipient) pair; the record is authoritative for what the
 * sending client displays to the user.
 *
 * @module
 */

import type { ReasonCode } from "../reasoncodes.js";

/** Lifecycle position per §2.5. */
export type QueueRecordState =
  | "queued"
  | "delivered"
  | "rejected"
  | "expired"
  | "canceled";

/** Report whether a state is terminal (no further transitions). */
export function isTerminalState(s: QueueRecordState): boolean {
  return s !== "queued";
}

/** Per-recipient queue state record. */
export interface QueueState {
  envelope_id: string;
  recipient: string;
  state: QueueRecordState;
  attempts: number;
  /** ISO 8601 UTC, or null if never attempted. */
  last_attempt_at: string | null;
  /** "delivered" | "rejected" | "silent" | null. */
  last_outcome: string | null;
  last_reason_code: ReasonCode | null;
  /** ISO 8601 UTC, or null on terminal records. */
  next_attempt_at: string | null;
  /** Effective deadline per §2.4. ISO 8601 UTC. */
  deadline: string;
  /**
   * Internal-only: wall-clock at which `state` transitioned to a
   * terminal value. Used by the §2.5 retention prune. Excluded from
   * canonical wire bytes; serialize with a custom replacer if
   * exporting.
   */
  terminal_at?: string;
}

/**
 * Transition `q` to `state`, recording the transition wall-clock
 * on `terminal_at` and clearing `next_attempt_at`. No-op when:
 *
 *  - `state` is non-terminal
 *  - `q` is already terminal (the §2.7.2 "MUST NOT override a prior
 *    terminal state" rule is the caller's responsibility)
 */
export function setTerminal(
  q: QueueState,
  state: QueueRecordState,
  now: Date,
): void {
  if (!isTerminalState(state)) {
    return;
  }
  if (isTerminalState(q.state)) {
    return;
  }
  q.state = state;
  q.next_attempt_at = null;
  q.terminal_at = now.toISOString().replace(/\.\d{3}Z$/, "Z");
}
