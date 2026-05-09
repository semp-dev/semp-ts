/**
 * Sending-side delivery scheduler per DELIVERY.md §2.3 + §2.5 + §2.7.
 *
 * Drives the §4.5 delivery queue by consuming the §2.3 retry helpers
 * and the §2.5 queue-state record against an injectable
 * {@link DeliverFunc}. Operators call {@link Scheduler.tick} on a
 * timer (every few seconds). Each tick:
 *
 *   - Pulls due records from the {@link SchedulerStore}.
 *   - Runs {@link DeliverFunc} against each.
 *   - Updates state per the per-attempt outcome:
 *     - `delivered` → state = `delivered`, emit event.
 *     - `rejected` (non-recoverable) → state = `rejected`, emit event.
 *     - `rejected` (recoverable) / `silent` / transport failure →
 *       schedule next attempt via `nextAttemptAt`.
 *     - Effective deadline reached → state = `expired`, emit event.
 *
 * @module
 */

import type { ReasonCode } from "../reasoncodes.js";

import {
  type RetryConfig,
  effectiveDeadline,
  isRecoverableReason,
  nextAttemptAt,
  sanitizeRetry,
} from "./retry.js";
import {
  type QueueRecordState,
  type QueueState,
  isTerminalState,
  setTerminal,
} from "./queue.js";
import type { CancelResult } from "./cancel.js";
import {
  type SubmissionEvent,
  newSubmissionEvent,
} from "./submission.js";

/** Outcome of a single delivery attempt. */
export interface AttemptResult {
  status: "delivered" | "rejected" | "silent";
  reasonCode?: string;
  reason?: string;
}

/** Performs a single delivery attempt against `(envelopeId, recipient)`. */
export type DeliverFunc = (
  envelopeId: string,
  recipient: string,
) => Promise<AttemptResult>;

/** Consumes terminal-state delivery events per §6.5. */
export type EventSink = (ev: SubmissionEvent) => void;

/** Persistence interface for queue records. */
export interface SchedulerStore {
  /** Insert or update a record. */
  put(q: QueueState): Promise<void>;
  /** Fetch a record by `(envelope_id, recipient)`, or `null`. */
  get(
    envelopeId: string,
    recipient: string,
  ): Promise<QueueState | null>;
  /**
   * Every non-terminal record whose `next_attempt_at` is at or
   * before `now`, ordered ascending by `next_attempt_at` with ties
   * broken by `envelope_id`.
   */
  dueRecords(now: Date): Promise<QueueState[]>;
  /**
   * Terminal records whose `terminal_at` is at or before `cutoff`.
   * Used by the retention prune.
   */
  listTerminalOlderThan(cutoff: Date): Promise<QueueState[]>;
  /** Remove a record. */
  delete(envelopeId: string, recipient: string): Promise<void>;
}

/** Inputs to {@link Scheduler}. */
export interface SchedulerConfig {
  store: SchedulerStore;
  deliver: DeliverFunc;
  /** Backoff policy. Defaults applied via {@link sanitizeRetry}. */
  retry?: RetryConfig;
  /**
   * Operator-configured retry horizon per §2.4. Defaults to
   * 72 hours; values above 7 days are clamped down.
   */
  maxRetryHorizonMs?: number;
  /** Optional terminal-event sink. */
  eventSink?: EventSink;
  /** Wall-clock hook. Defaults to `() => new Date()`. */
  now?: () => Date;
}

/** Sentinel error: a tick is already in progress. */
export class TickInProgressError extends Error {
  override readonly name = "TickInProgressError";
  constructor() {
    super("delivery: scheduler tick already in progress");
  }
}

/** Sentinel error: no queue record for the requested key. */
export class UnknownRecordError extends Error {
  override readonly name = "UnknownRecordError";
  constructor(envelopeId: string, recipient: string) {
    super(
      `delivery: no queue record for envelope_id=${JSON.stringify(envelopeId)} recipient=${JSON.stringify(recipient)}`,
    );
  }
}

/**
 * Sending-side delivery scheduler. Single-process; the JS
 * run-to-completion model gives effectively-atomic Tick semantics.
 * `tickInFlight` is enforced by a software latch so concurrent
 * calls return {@link TickInProgressError}.
 */
export class Scheduler {
  private readonly store: SchedulerStore;
  private readonly deliver: DeliverFunc;
  private readonly retry: RetryConfig;
  private readonly horizonMs: number;
  private readonly eventSink: EventSink | null;
  private readonly nowFn: () => Date;
  private tickInFlight = false;

  constructor(cfg: SchedulerConfig) {
    if (cfg.store === undefined) {
      throw new Error("delivery: scheduler requires a store");
    }
    if (cfg.deliver === undefined) {
      throw new Error("delivery: scheduler requires a deliver");
    }
    this.store = cfg.store;
    this.deliver = cfg.deliver;
    this.retry = sanitizeRetry(cfg.retry ?? {});
    this.horizonMs = cfg.maxRetryHorizonMs ?? 72 * 3_600_000;
    this.eventSink = cfg.eventSink ?? null;
    this.nowFn = cfg.now ?? (() => new Date());
  }

  /**
   * Insert a new queue record for `(envelopeId, recipient)`. State
   * starts at `queued`; `next_attempt_at = now` (deliver on next
   * tick); `deadline = effectiveDeadline(postmarkExpires, now,
   * horizon)`.
   *
   * Throws when a record for the same `(envelopeId, recipient)`
   * already exists.
   */
  async enqueue(
    envelopeId: string,
    recipient: string,
    postmarkExpires: Date,
  ): Promise<void> {
    if (envelopeId === "") {
      throw new Error("delivery: enqueue empty envelope_id");
    }
    if (recipient === "") {
      throw new Error("delivery: enqueue empty recipient");
    }
    const now = this.nowFn();
    const existing = await this.store.get(envelopeId, recipient);
    if (existing !== null) {
      throw new Error(
        `delivery: queue record already exists for (${envelopeId}, ${recipient})`,
      );
    }
    const deadline = effectiveDeadline(
      postmarkExpires,
      now,
      this.horizonMs,
    );
    const q: QueueState = {
      envelope_id: envelopeId,
      recipient,
      state: "queued",
      attempts: 0,
      last_attempt_at: null,
      last_outcome: null,
      last_reason_code: null,
      next_attempt_at: isoSecond(now),
      deadline: isoSecond(deadline),
    };
    await this.store.put(q);
  }

  /**
   * Pull every record whose `next_attempt_at` has passed and
   * process it. Returns the number of records advanced (terminal
   * or otherwise) and, on partial failure, the first error
   * encountered (per-record errors do not abort the tick).
   *
   * Throws {@link TickInProgressError} if a concurrent tick is
   * already running.
   */
  async tick(): Promise<{ advanced: number; firstError?: Error }> {
    if (this.tickInFlight) {
      throw new TickInProgressError();
    }
    this.tickInFlight = true;
    try {
      const now = this.nowFn();
      const due = await this.store.dueRecords(now);
      let advanced = 0;
      let firstError: Error | undefined;
      for (const q of due) {
        try {
          if (isTerminalState(q.state)) {
            continue;
          }
          if (now.getTime() >= Date.parse(q.deadline)) {
            this.transitionExpired(q, now);
            await this.store.put(q);
            advanced += 1;
            continue;
          }
          await this.runAttempt(q, now);
          await this.store.put(q);
          advanced += 1;
        } catch (err) {
          if (firstError === undefined) {
            firstError =
              err instanceof Error
                ? err
                : new Error(`tick error: ${String(err)}`);
          }
        }
      }
      return firstError === undefined
        ? { advanced }
        : { advanced, firstError };
    } finally {
      this.tickInFlight = false;
    }
  }

  /**
   * Transition `(envelopeId, recipient)` to the `canceled` terminal
   * state per §2.7. Returns the resulting {@link CancelResult}.
   * Idempotent: cancellation of a record already in a terminal
   * state is a no-op that returns the prior state.
   */
  async cancel(
    envelopeId: string,
    recipient: string,
  ): Promise<CancelResult> {
    const now = this.nowFn();
    const q = await this.store.get(envelopeId, recipient);
    if (q === null) {
      throw new UnknownRecordError(envelopeId, recipient);
    }
    if (isTerminalState(q.state)) {
      return {
        recipient,
        state: q.state,
        reason: `already ${q.state}; cancellation is a no-op per §2.7.4`,
      };
    }
    setTerminal(q, "canceled", now);
    await this.store.put(q);
    this.emit(q, "client-initiated cancellation");
    return { recipient, state: "canceled" };
  }

  /**
   * Cancel every still-non-terminal record for `envelopeId` across
   * all recipients. Returns one {@link CancelResult} per record
   * observed.
   */
  async cancelEnvelope(envelopeId: string): Promise<CancelResult[]> {
    if (envelopeId === "") {
      throw new Error("delivery: cancelEnvelope empty envelope_id");
    }
    const now = this.nowFn();
    // dueRecords returns non-terminal records ordered by NextAttempt;
    // pulling with a far-future cap is the simplest way to enumerate.
    const all = await this.store.dueRecords(
      new Date(now.getTime() + this.horizonMs * 2),
    );
    const matches = all.filter((q) => q.envelope_id === envelopeId);
    const out: CancelResult[] = [];
    for (const q of matches) {
      if (isTerminalState(q.state)) {
        out.push({
          recipient: q.recipient,
          state: q.state,
          reason: `already ${q.state}; cancellation is a no-op per §2.7.4`,
        });
        continue;
      }
      setTerminal(q, "canceled", now);
      await this.store.put(q);
      this.emit(q, "client-initiated whole-envelope cancellation");
      out.push({ recipient: q.recipient, state: "canceled" });
    }
    return out;
  }

  /**
   * Evict terminal records whose `terminal_at` is at or before
   * `now - retentionMs` per §2.5 retention. Returns the count
   * pruned.
   */
  async pruneTerminal(retentionMs: number): Promise<number> {
    const cutoff = new Date(this.nowFn().getTime() - retentionMs);
    const stale = await this.store.listTerminalOlderThan(cutoff);
    let n = 0;
    for (const q of stale) {
      await this.store.delete(q.envelope_id, q.recipient);
      n += 1;
    }
    return n;
  }

  // ---------------------------------------------------------------------------

  private async runAttempt(q: QueueState, now: Date): Promise<void> {
    const res = await this.deliver(q.envelope_id, q.recipient);
    q.attempts += 1;
    q.last_attempt_at = isoSecond(now);
    q.last_outcome = res.status;
    q.last_reason_code =
      res.reasonCode !== undefined && res.reasonCode !== ""
        ? (res.reasonCode as ReasonCode)
        : null;

    if (res.status === "delivered") {
      this.transitionTerminal(q, "delivered", now, res.reason);
      return;
    }
    if (
      res.status === "rejected" &&
      !isRecoverableReason(res.reasonCode ?? "")
    ) {
      this.transitionTerminal(q, "rejected", now, res.reason);
      return;
    }
    // Recoverable rejection or silent → schedule next attempt.
    let next: Date;
    try {
      next = nextAttemptAt(this.retry, now, q.attempts - 1);
    } catch {
      // Pathological: schedule a conservative fallback.
      next = new Date(now.getTime() + 1_000);
    }
    if (next.getTime() > Date.parse(q.deadline)) {
      // Next attempt would land past deadline → expire instead.
      this.transitionExpired(q, now);
      return;
    }
    q.next_attempt_at = isoSecond(next);
  }

  private transitionTerminal(
    q: QueueState,
    state: QueueRecordState,
    now: Date,
    reason: string | undefined,
  ): void {
    if (isTerminalState(q.state)) {
      return;
    }
    setTerminal(q, state, now);
    this.emit(q, reason);
  }

  private transitionExpired(q: QueueState, now: Date): void {
    if (isTerminalState(q.state)) {
      return;
    }
    setTerminal(q, "expired", now);
    this.emit(q, undefined);
  }

  private emit(q: QueueState, reason: string | undefined): void {
    if (this.eventSink === null) {
      return;
    }
    const status =
      q.state === "delivered" ? "delivered" : "rejected";
    const opts: {
      reasonCode?: string;
      reason?: string;
      nowFn?: () => Date;
    } = {};
    if (q.last_reason_code !== null) {
      opts.reasonCode = q.last_reason_code;
    }
    if (reason !== undefined && reason !== "") {
      opts.reason = reason;
    }
    if (q.terminal_at !== undefined && q.terminal_at !== "") {
      opts.nowFn = () => new Date(q.terminal_at!);
    }
    const ev = newSubmissionEvent(
      q.envelope_id,
      q.recipient,
      status,
      opts,
    );
    this.eventSink(ev);
  }
}

/**
 * Reference in-memory {@link SchedulerStore}. Tests / single-process
 * demos only — production deployments back the queue with durable
 * storage per DELIVERY.md §2.1.
 */
export class InMemorySchedulerStore implements SchedulerStore {
  private readonly records = new Map<string, QueueState>();

  private static keyOf(envelopeId: string, recipient: string): string {
    return `${envelopeId}\x00${recipient}`;
  }

  async put(q: QueueState): Promise<void> {
    this.records.set(InMemorySchedulerStore.keyOf(q.envelope_id, q.recipient), {
      ...q,
    });
  }

  async get(
    envelopeId: string,
    recipient: string,
  ): Promise<QueueState | null> {
    const r = this.records.get(
      InMemorySchedulerStore.keyOf(envelopeId, recipient),
    );
    return r === undefined ? null : { ...r };
  }

  async dueRecords(now: Date): Promise<QueueState[]> {
    const out: QueueState[] = [];
    for (const q of this.records.values()) {
      if (isTerminalState(q.state)) {
        continue;
      }
      if (q.next_attempt_at === null) {
        continue;
      }
      if (Date.parse(q.next_attempt_at) <= now.getTime()) {
        out.push({ ...q });
      }
    }
    out.sort((a, b) => {
      const at = a.next_attempt_at !== null ? Date.parse(a.next_attempt_at) : 0;
      const bt = b.next_attempt_at !== null ? Date.parse(b.next_attempt_at) : 0;
      if (at !== bt) {
        return at - bt;
      }
      return a.envelope_id < b.envelope_id ? -1 : 1;
    });
    return out;
  }

  async listTerminalOlderThan(cutoff: Date): Promise<QueueState[]> {
    const out: QueueState[] = [];
    for (const q of this.records.values()) {
      if (
        isTerminalState(q.state) &&
        q.terminal_at !== undefined &&
        Date.parse(q.terminal_at) <= cutoff.getTime()
      ) {
        out.push({ ...q });
      }
    }
    return out;
  }

  async delete(envelopeId: string, recipient: string): Promise<void> {
    this.records.delete(InMemorySchedulerStore.keyOf(envelopeId, recipient));
  }
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
