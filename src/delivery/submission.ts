/**
 * SEMP_SUBMISSION wire shapes per CLIENT.md §6.1, §6.5 and
 * DELIVERY.md §2.7.
 *
 * `SubmissionResponse` is the synchronous outcome a home server
 * returns to a client after the client submits an envelope.
 * `SubmissionEvent` is the asynchronous follow-up notification a
 * server sends when a previously-queued envelope's outcome resolves.
 *
 * @module
 */

import type { Acknowledgment } from "./ack.js";
import type { DeliveryReceipt } from "./receipt.js";

/** Wire-level type discriminator. */
export const SubmissionType = "SEMP_SUBMISSION";

/** Schema version. */
export const SubmissionVersion = "1.0.0";

/**
 * Discriminator for which submission message variant this is.
 * `cancel` and `cancel_response` are added by the cancel module
 * per DELIVERY.md §2.7.
 */
export type SubmissionStep =
  | "response"
  | "event"
  | "cancel"
  | "cancel_response";

/** Per-recipient delivery outcome per CLIENT.md §6.2. */
export interface SubmissionResult {
  recipient: string;
  status: Acknowledgment | "queued" | "no_receipt";
  reason_code?: string;
  reason?: string;
  /**
   * Populated when `status === "delivered"` per DELIVERY.md
   * §1.1.1.5; `null` otherwise. Sender-side servers MUST verify
   * before treating the result as terminal delivered (§1.1.1.6).
   */
  receipt?: DeliveryReceipt | null;
}

/** SEMP_SUBMISSION response per CLIENT.md §6.1. */
export interface SubmissionResponse {
  type: typeof SubmissionType;
  step: "response";
  version: string;
  envelope_id: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  results: SubmissionResult[];
}

/** Construct a {@link SubmissionResponse}. */
export function newSubmissionResponse(
  envelopeId: string,
  results: SubmissionResult[],
  nowFn: () => Date = () => new Date(),
): SubmissionResponse {
  if (envelopeId === "") {
    throw new Error("delivery: empty envelope_id");
  }
  return {
    type: SubmissionType,
    step: "response",
    version: SubmissionVersion,
    envelope_id: envelopeId,
    timestamp: isoSecond(nowFn()),
    results,
  };
}

/**
 * Asynchronous follow-up sent when a queued envelope's outcome
 * resolves per CLIENT.md §6.5. Single per-recipient event rather
 * than a batch.
 */
export interface SubmissionEvent {
  type: typeof SubmissionType;
  step: "event";
  version: string;
  envelope_id: string;
  recipient: string;
  status: Acknowledgment | "queued" | "no_receipt";
  reason_code?: string;
  reason?: string;
  /** ISO 8601 UTC. */
  timestamp: string;
}

/** Construct a {@link SubmissionEvent}. */
export function newSubmissionEvent(
  envelopeId: string,
  recipient: string,
  status: SubmissionEvent["status"],
  opts: { reason_code?: string; reason?: string; nowFn?: () => Date } = {},
): SubmissionEvent {
  if (envelopeId === "") {
    throw new Error("delivery: empty envelope_id");
  }
  if (recipient === "") {
    throw new Error("delivery: empty recipient");
  }
  const ev: SubmissionEvent = {
    type: SubmissionType,
    step: "event",
    version: SubmissionVersion,
    envelope_id: envelopeId,
    recipient,
    status,
    timestamp: isoSecond((opts.nowFn ?? (() => new Date()))()),
  };
  if (opts.reason_code !== undefined) {
    ev.reason_code = opts.reason_code;
  }
  if (opts.reason !== undefined) {
    ev.reason = opts.reason;
  }
  return ev;
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
