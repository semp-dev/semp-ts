/**
 * Home-server closure driver per CLOSURE.md §3 + §4 + §5.
 *
 * Orchestrates closure lifecycle on a {@link ClosureStore}:
 *  - {@link Driver.submit}: accept a request or cancel
 *  - {@link Driver.tick}: drive due requests to finalization
 *  - {@link Driver.isAccountClosed}: §5 ingress enforcement
 *  - {@link Driver.recipientPolicy}: returns a delivery-policy
 *    adapter that rejects envelopes addressed to closed accounts
 *
 * @module
 */

import type { Acknowledgment, RecipientStatus } from "../delivery/index.js";
import type { ReasonCode } from "../reasoncodes.js";

import {
  type ClosureRecord,
  isFinalizable,
  validateClosureRecord,
} from "./closure.js";
import { type ClosureStore, AlreadyPendingError } from "./store.js";

/** Inputs to the {@link Driver} constructor. */
export interface DriverConfig {
  /** Persistence backend. Tests pass {@link InMemoryClosureStore}. */
  store: ClosureStore;
  /** Wall-clock provider. Defaults to `() => new Date()`. */
  nowFn?: () => Date;
}

/**
 * Outcome of a {@link Driver.submit} call.
 *
 *  - `accepted`: the request was inserted (for `step=request`) or
 *    a pending request was canceled (for `step=cancel`).
 *  - `already_pending`: a request is already pending for this
 *    user_id; the §2.4 rule rejects double-requests.
 *  - `not_pending`: a cancel arrived for an account with no
 *    pending request — the spec treats this as a no-op success.
 *  - `invalid`: the record failed structural validation.
 */
export type SubmitResult =
  | { kind: "accepted" }
  | { kind: "already_pending" }
  | { kind: "not_pending" }
  | { kind: "invalid"; reason: string };

/** Outcome entry returned by {@link Driver.tick}. */
export interface FinalizeResult {
  user_id: string;
  finalized_at: Date;
}

/** Closure driver. */
export class Driver {
  private readonly store: ClosureStore;
  private readonly nowFn: () => Date;

  constructor(cfg: DriverConfig) {
    this.store = cfg.store;
    this.nowFn = cfg.nowFn ?? (() => new Date());
  }

  /**
   * Apply `record` to the store. Caller MUST verify the record's
   * signature and authority (§2.3 — the issuing device must be a
   * full-access device of the account) BEFORE calling submit.
   */
  async submit(record: ClosureRecord): Promise<SubmitResult> {
    try {
      validateClosureRecord(record);
    } catch (err) {
      return {
        kind: "invalid",
        reason: err instanceof Error ? err.message : String(err),
      };
    }

    if (record.step === "request") {
      try {
        await this.store.putPending(record);
        return { kind: "accepted" };
      } catch (err) {
        if (err instanceof AlreadyPendingError) {
          return { kind: "already_pending" };
        }
        throw err;
      }
    }
    // step === "cancel"
    const existing = await this.store.getPending(record.user_id);
    if (existing === null) {
      return { kind: "not_pending" };
    }
    await this.store.deletePending(record.user_id);
    return { kind: "accepted" };
  }

  /**
   * Drive any pending requests whose finalization timestamp has
   * arrived to the finalized state. Returns the list of accounts
   * finalized in this tick (deterministically ordered).
   */
  async tick(): Promise<FinalizeResult[]> {
    const now = this.nowFn();
    const due = await this.store.duePending(now);
    const out: FinalizeResult[] = [];
    for (const r of due) {
      if (!isFinalizable(r, now)) {
        continue; // defensive
      }
      await this.store.putFinalized(r.user_id, now);
      await this.store.deletePending(r.user_id);
      out.push({ user_id: r.user_id, finalized_at: now });
    }
    return out;
  }

  /**
   * Report whether `userId`'s account is currently closed within
   * the §6.1 retention window.
   *
   * Returns true when `getFinalized(userId)` yields a timestamp
   * (the store enforces retention via its prune path; once an
   * entry is pruned, this returns false and the local-part is
   * eligible for §6.2 reassignment).
   */
  async isAccountClosed(userId: string): Promise<boolean> {
    const finalized = await this.store.getFinalized(userId);
    return finalized !== null;
  }

  /**
   * Return a per-recipient delivery-policy adapter that rejects
   * envelopes addressed to closed accounts per §5.1, preserving
   * existence indistinguishability per DESIGN.md §2.7 (the
   * `policy_forbidden` reason is the same one a non-existent
   * address receives).
   *
   * Pass `useSilent: true` to return the `silent` acknowledgment
   * instead. Both preserve indistinguishability; the choice is
   * operator policy.
   */
  recipientPolicy(opts: { useSilent?: boolean } = {}): RecipientPolicyFunc {
    return async (recipientAddress) => {
      let closed: boolean;
      try {
        closed = await this.isAccountClosed(recipientAddress);
      } catch {
        // Fail open per §5.1: a transient store error MUST NOT
        // silently drop deliveries to active accounts.
        return null;
      }
      if (!closed) {
        return null;
      }
      if (opts.useSilent === true) {
        return { acknowledgment: "silent" };
      }
      return {
        acknowledgment: "rejected",
        reason_code: "policy_forbidden",
        reason: "recipient policy",
      };
    };
  }
}

/**
 * Per-recipient policy gate signature. Returns `null` to pass
 * through to subsequent checks; returns a structured outcome to
 * short-circuit delivery.
 */
export type RecipientPolicyFunc = (recipientAddress: string) => Promise<
  | null
  | {
      acknowledgment: Acknowledgment;
      reason_code?: ReasonCode;
      reason?: string;
      recipient_status?: RecipientStatus;
    }
>;
