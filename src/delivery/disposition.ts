/**
 * Delivery disposition data per DELIVERY.md §3.2 + CLIENT.md §4.5.7.
 *
 * The `delivery-disposition` sync kind is the control signal a
 * staged device emits to tell the home server whether a held
 * envelope should advance to the next stage or be suppressed.
 *
 * @module
 */

/** The literal `kind` string identifying a delivery-disposition sync marker. */
export const DispositionKind = "delivery-disposition";

/** Disposition decision per CLIENT.md §4.5.7. */
export type DispositionDecision = "advance" | "suppress";

/** Recommended reason tags per CLIENT.md §4.5.7. Operators MAY define more. */
export const DispositionReasonSpam = "spam";
export const DispositionReasonAccepted = "accepted";
export const DispositionReasonPolicy = "policy";
export const DispositionReasonOther = "other";

/**
 * Payload of a `delivery-disposition` sync marker. Carries the
 * inner `data` object of the `semp.dev/device-sync` extension when
 * the extension's `kind` is `"delivery-disposition"`.
 */
export interface Disposition {
  kind: typeof DispositionKind;
  source_envelope_id: string;
  disposition: DispositionDecision;
  reason?: string;
  device_id: string;
}

/**
 * Validate `d` is structurally well-formed per CLIENT.md §4.5.7.
 * Does NOT verify authentication; the home server verifies §3.2.5
 * (session belongs to `device_id`) at receipt.
 */
export function validateDisposition(d: Disposition): void {
  if (d === undefined || d === null) {
    throw new Error("delivery: nil disposition");
  }
  if (d.kind !== DispositionKind) {
    throw new Error(
      `delivery: disposition kind ${JSON.stringify(d.kind)}, want ${JSON.stringify(DispositionKind)}`,
    );
  }
  if (d.source_envelope_id === "") {
    throw new Error("delivery: disposition missing source_envelope_id");
  }
  if (d.device_id === "") {
    throw new Error("delivery: disposition missing device_id");
  }
  if (d.disposition === undefined || (d.disposition as string) === "") {
    throw new Error("delivery: disposition missing decision");
  }
  if (d.disposition !== "advance" && d.disposition !== "suppress") {
    throw new Error(
      `delivery: disposition decision ${JSON.stringify(d.disposition)} is not a valid value`,
    );
  }
}

/** Outcome of aggregating dispositions at one stage per §3.2.3. */
export type StageOutcome = "advance" | "suppress";

/**
 * Apply the §3.2.3 conservative aggregation rule across the
 * dispositions collected at one stage:
 *
 *   - If any disposition is `suppress`, return `"suppress"`.
 *   - Otherwise return `"advance"` (covers "any advance" and "no
 *     dispositions at all" via §3.2.4 fail-open on timeout).
 *
 * Does NOT itself enforce the §3.2.5 authentication rules; the
 * caller filters out late or off-stage dispositions before
 * aggregating.
 */
export function aggregateDispositions(ds: Disposition[]): StageOutcome {
  for (const d of ds) {
    if (d.disposition === "suppress") {
      return "suppress";
    }
  }
  return "advance";
}

/**
 * Recommended stage timeout per DELIVERY.md §3.2.2. Operators MAY
 * configure longer windows.
 */
export const DefaultStageTimeoutMs = 30_000;

/**
 * One stage's pending-device set inside a {@link StagedHeld}
 * record per §3.2.2.
 */
export interface StagedHeldStage {
  /** 1-based stage index; lower delivers first. */
  stage: number;
  /**
   * Devices at this stage that the held envelope was wrapped for
   * and that have not yet emitted a disposition.
   */
  pending_device_ids: string[];
  /** Dispositions collected so far at this stage. */
  dispositions: Disposition[];
}

/**
 * One envelope held in the staged-delivery queue per §3.2.2. The
 * envelope itself is NOT stored twice - this record is the
 * per-stage pointer set the server maintains.
 */
export interface StagedHeld {
  /** `postmark.id` of the held envelope. */
  envelope_id: string;
  /**
   * Ordered list of stages still to deliver. `stages[0]` is the
   * current pending stage; lower stages have already delivered or
   * been bypassed.
   */
  stages: StagedHeldStage[];
  /**
   * Wall-clock time at which the current stage times out (set by
   * the home server when entering a stage). ISO 8601 UTC. Empty
   * string means "no deadline set".
   */
  deadline: string;
}

/**
 * Whether the wait at the current stage MUST terminate per §3.2.2.
 * Either every device at the stage has emitted a disposition, or
 * the deadline has passed.
 *
 * Does NOT return the outcome; the caller follows up with
 * {@link aggregateDispositions} to compute that.
 *
 * @param stage - the current stage record
 * @param now - current wall-clock
 * @param deadline - ISO 8601 UTC string; empty means "no deadline"
 */
export function isStageComplete(
  stage: StagedHeldStage,
  now: Date,
  deadline: string,
): boolean {
  if (stage === undefined || stage === null) {
    return true;
  }
  if (stage.pending_device_ids.length === 0) {
    return true;
  }
  if (deadline !== "") {
    const ms = Date.parse(deadline);
    if (!Number.isNaN(ms) && now.getTime() >= ms) {
      return true;
    }
  }
  // All pending devices have emitted? Build a set of devices
  // already represented in `dispositions` and check.
  const seen = new Set<string>();
  for (const d of stage.dispositions) {
    seen.add(d.device_id);
  }
  for (const id of stage.pending_device_ids) {
    if (!seen.has(id)) {
      return false;
    }
  }
  return true;
}
