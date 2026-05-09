/**
 * SEMP_SUBMISSION cancel / cancel_response wire shapes per
 * DELIVERY.md §2.7.
 *
 * @module
 */

import { type QueueRecordState } from "./queue.js";
import {
  type SubmissionStep,
  SubmissionType,
  SubmissionVersion,
} from "./submission.js";

/**
 * SEMP_SUBMISSION cancel request per §2.7.1 / CLIENT.md §6.6.
 *
 * The client identifies the target envelope by `envelope_id`. An
 * optional `recipient` narrows cancellation to one queue-state
 * record; an empty / absent `recipient` means whole-envelope cancel
 * (every still-non-terminal record).
 */
export interface CancelRequest {
  type: typeof SubmissionType;
  step: "cancel";
  version: string;
  envelope_id: string;
  recipient?: string;
  /** ISO 8601 UTC. */
  timestamp: string;
}

/** Construct a {@link CancelRequest}. */
export function newCancelRequest(
  envelopeId: string,
  opts: { recipient?: string; nowFn?: () => Date } = {},
): CancelRequest {
  if (envelopeId === "") {
    throw new Error("delivery: empty envelope_id");
  }
  const r: CancelRequest = {
    type: SubmissionType,
    step: "cancel",
    version: SubmissionVersion,
    envelope_id: envelopeId,
    timestamp: isoSecond((opts.nowFn ?? (() => new Date()))()),
  };
  if (opts.recipient !== undefined && opts.recipient !== "") {
    r.recipient = opts.recipient;
  }
  return r;
}

/** One entry in {@link CancelResponse.results} per §2.7.2. */
export interface CancelResult {
  recipient: string;
  state: QueueRecordState;
  /**
   * Optional human-readable explanation for unusual outcomes
   * (e.g. "already delivered, cancellation no-op per §2.7.4").
   */
  reason?: string;
}

/**
 * Per-record summary returned by the sending server per §2.7.2.
 *
 * A no-op (record was already terminal) returns the prior terminal
 * state without changing it; the caller distinguishes by comparing
 * `state` to the expected `"canceled"`.
 */
export interface CancelResponse {
  type: typeof SubmissionType;
  step: "cancel_response";
  version: string;
  envelope_id: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  results: CancelResult[];
}

/** Construct a {@link CancelResponse}. */
export function newCancelResponse(
  envelopeId: string,
  results: CancelResult[],
  nowFn: () => Date = () => new Date(),
): CancelResponse {
  if (envelopeId === "") {
    throw new Error("delivery: empty envelope_id");
  }
  return {
    type: SubmissionType,
    step: "cancel_response",
    version: SubmissionVersion,
    envelope_id: envelopeId,
    timestamp: isoSecond(nowFn()),
    results,
  };
}

// Re-export the shared submission step set so callers can discriminate
// without two imports.
export type { SubmissionStep };

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
