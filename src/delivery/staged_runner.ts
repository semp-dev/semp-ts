/**
 * Staged-delivery runtime per DELIVERY.md §3.2.
 *
 * Drives the wait-and-aggregate loop:
 *
 *   - {@link StagedRunner.hold} registers a held envelope with its
 *     stage partition (output of
 *     {@link "./stage_partition".partitionStages}) and immediately
 *     delivers to the lowest stage.
 *   - {@link StagedRunner.ingestDisposition} records a stage-N
 *     device's decision per §3.2.5.
 *   - {@link StagedRunner.tick} advances envelopes whose current
 *     stage has completed (every pending device emitted, or the
 *     stage timeout elapsed per §3.2.4).
 *
 * Single-process, callable across many envelopes. JS event-loop
 * concurrency: each call is run-to-completion atomic. There is no
 * cross-thread state.
 *
 * @module
 */

import {
  type Disposition,
  type StagedHeld,
  type StagedHeldStage,
  DefaultStageTimeoutMs,
  aggregateDispositions,
  isStageComplete,
  validateDisposition,
} from "./disposition.js";

/** Hook delivering an envelope to one stage's pending device set. */
export type StageDeliverFunc = (
  envelopeId: string,
  stage: number,
  deviceIds: string[],
) => Promise<void>;

/** Hook invoked when aggregation at any stage produces `suppress`. */
export type StageSuppressFunc = (
  envelopeId: string,
  stage: number,
) => Promise<void>;

/** Hook invoked when every stage advances without suppress. */
export type StageCompleteFunc = (envelopeId: string) => Promise<void>;

/** Inputs to {@link StagedRunner}. */
export interface StagedRunnerConfig {
  deliver: StageDeliverFunc;
  suppress: StageSuppressFunc;
  complete: StageCompleteFunc;
  /** Per-stage wait window. Defaults to {@link DefaultStageTimeoutMs}. */
  stageTimeoutMs?: number;
  /** Wall-clock hook; defaults to `() => new Date()`. */
  now?: () => Date;
}

/** Sentinel error: envelope is already in the held queue. */
export class EnvelopeAlreadyHeldError extends Error {
  override readonly name = "EnvelopeAlreadyHeldError";
  constructor(envelopeId: string) {
    super(`delivery: envelope ${JSON.stringify(envelopeId)} is already held`);
  }
}

/** Sentinel error: envelope is not in the held queue. */
export class EnvelopeNotHeldError extends Error {
  override readonly name = "EnvelopeNotHeldError";
  constructor(envelopeId: string) {
    super(`delivery: envelope ${JSON.stringify(envelopeId)} is not held`);
  }
}

/**
 * Staged-delivery runtime. Concurrency-safe within a single JS event
 * loop (run-to-completion).
 */
export class StagedRunner {
  private readonly cfg: Required<
    Omit<StagedRunnerConfig, "stageTimeoutMs" | "now">
  > & { stageTimeoutMs: number; now: () => Date };
  private readonly heldMap = new Map<string, StagedHeld>();

  constructor(cfg: StagedRunnerConfig) {
    if (cfg.deliver === undefined) {
      throw new Error("delivery: staged runner requires deliver");
    }
    if (cfg.suppress === undefined) {
      throw new Error("delivery: staged runner requires suppress");
    }
    if (cfg.complete === undefined) {
      throw new Error("delivery: staged runner requires complete");
    }
    this.cfg = {
      deliver: cfg.deliver,
      suppress: cfg.suppress,
      complete: cfg.complete,
      stageTimeoutMs:
        cfg.stageTimeoutMs !== undefined && cfg.stageTimeoutMs > 0
          ? cfg.stageTimeoutMs
          : DefaultStageTimeoutMs,
      now: cfg.now ?? (() => new Date()),
    };
  }

  /**
   * Register `envelopeId` with `stages` and deliver to the lowest
   * stage. `stages[i].stage` MUST be monotonically increasing.
   * Stages with empty `pending_device_ids` are pruned.
   */
  async hold(envelopeId: string, stages: StagedHeldStage[]): Promise<void> {
    if (envelopeId === "") {
      throw new Error("delivery: hold empty envelope_id");
    }
    const cleaned: StagedHeldStage[] = [];
    for (const s of stages) {
      if (s.pending_device_ids.length === 0) {
        continue;
      }
      cleaned.push({
        stage: s.stage,
        pending_device_ids: s.pending_device_ids.slice(),
        dispositions: [],
      });
    }
    if (cleaned.length === 0) {
      throw new Error(
        "delivery: hold partition has no pending devices at any stage",
      );
    }
    for (let i = 1; i < cleaned.length; i++) {
      if (cleaned[i]!.stage <= cleaned[i - 1]!.stage) {
        throw new Error(
          `delivery: hold stages not monotonically increasing: stage[${i}]=${cleaned[i]!.stage} <= stage[${i - 1}]=${cleaned[i - 1]!.stage}`,
        );
      }
    }
    if (this.heldMap.has(envelopeId)) {
      throw new EnvelopeAlreadyHeldError(envelopeId);
    }
    const deadline = isoSecond(
      new Date(this.cfg.now().getTime() + this.cfg.stageTimeoutMs),
    );
    const rec: StagedHeld = {
      envelope_id: envelopeId,
      stages: cleaned,
      deadline,
    };
    this.heldMap.set(envelopeId, rec);
    try {
      await this.cfg.deliver(
        envelopeId,
        cleaned[0]!.stage,
        cleaned[0]!.pending_device_ids,
      );
    } catch (err) {
      // Best-effort cleanup so a retry can re-hold.
      this.heldMap.delete(envelopeId);
      throw new Error(
        `delivery: stage ${cleaned[0]!.stage} deliver: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  /**
   * Record `d` for `envelopeId`'s current stage per §3.2.5.
   *
   * `submitterDeviceId` is the device_id bound to the session that
   * delivered the disposition; it MUST equal `d.device_id`.
   *
   * Idempotent on repeats from the same device - keeps the FIRST
   * disposition (conservative aggregation).
   */
  ingestDisposition(
    envelopeId: string,
    submitterDeviceId: string,
    d: Disposition,
  ): void {
    validateDisposition(d);
    if (submitterDeviceId === "") {
      throw new Error(
        "delivery: ingest: submitter device_id is required for §3.2.5 authentication",
      );
    }
    if (submitterDeviceId !== d.device_id) {
      throw new Error(
        `delivery: ingest: submitter ${JSON.stringify(submitterDeviceId)} does not match disposition device_id ${JSON.stringify(d.device_id)} (§3.2.5)`,
      );
    }
    const rec = this.heldMap.get(envelopeId);
    if (rec === undefined) {
      throw new Error(
        `delivery: ingest: no held envelope for ${JSON.stringify(envelopeId)}`,
      );
    }
    if (rec.stages.length === 0) {
      throw new Error(
        `delivery: ingest: envelope ${JSON.stringify(envelopeId)} has no remaining stages`,
      );
    }
    const current = rec.stages[0]!;
    if (!current.pending_device_ids.includes(d.device_id)) {
      throw new Error(
        `delivery: ingest: device ${JSON.stringify(d.device_id)} is not in current stage ${current.stage}'s pending set (§3.2.5)`,
      );
    }
    for (const prior of current.dispositions) {
      if (prior.device_id === d.device_id) {
        // Idempotent on a repeat: keep the first vote.
        return;
      }
    }
    current.dispositions.push(d);
  }

  /**
   * Advance every held envelope whose current stage is complete.
   * Returns the number of envelopes advanced and the first
   * non-fatal callback error encountered (per-envelope errors do
   * not abort the tick).
   */
  async tick(): Promise<{ advanced: number; firstError?: Error }> {
    interface Pending {
      envelopeId: string;
      outcome: "advance" | "suppress";
      stage: number;
      nextStage?: number;
      nextDevs?: string[];
      done?: boolean;
    }
    const toRun: Pending[] = [];
    const now = this.cfg.now();

    for (const [id, rec] of this.heldMap) {
      if (rec.stages.length === 0) {
        continue;
      }
      const current = rec.stages[0]!;
      if (!isStageComplete(current, now, rec.deadline)) {
        continue;
      }
      const outcome = aggregateDispositions(current.dispositions);
      if (outcome === "suppress") {
        toRun.push({ envelopeId: id, outcome, stage: current.stage });
        this.heldMap.delete(id);
        continue;
      }
      // Advance: pop the current stage, deliver to next if any.
      rec.stages.shift();
      if (rec.stages.length === 0) {
        toRun.push({
          envelopeId: id,
          outcome,
          stage: current.stage,
          done: true,
        });
        this.heldMap.delete(id);
        continue;
      }
      const next = rec.stages[0]!;
      rec.deadline = isoSecond(
        new Date(now.getTime() + this.cfg.stageTimeoutMs),
      );
      toRun.push({
        envelopeId: id,
        outcome,
        stage: current.stage,
        nextStage: next.stage,
        nextDevs: next.pending_device_ids.slice(),
      });
    }

    // Sort so callback order is deterministic across runs.
    toRun.sort((a, b) =>
      a.envelopeId < b.envelopeId ? -1 : a.envelopeId > b.envelopeId ? 1 : 0,
    );

    let firstErr: Error | undefined;
    for (const p of toRun) {
      try {
        if (p.outcome === "suppress") {
          await this.cfg.suppress(p.envelopeId, p.stage);
          continue;
        }
        if (p.done === true) {
          await this.cfg.complete(p.envelopeId);
          continue;
        }
        await this.cfg.deliver(p.envelopeId, p.nextStage!, p.nextDevs!);
      } catch (err) {
        if (firstErr === undefined) {
          firstErr =
            err instanceof Error
              ? err
              : new Error(`staged tick callback: ${String(err)}`);
        }
      }
    }
    return firstErr === undefined
      ? { advanced: toRun.length }
      : { advanced: toRun.length, firstError: firstErr };
  }

  /**
   * Recompute a held envelope's stage partition per §3.2.6 in
   * response to a delegated device's certificate being updated or
   * revoked while the envelope is in flight. `newStages` is the
   * freshly-computed partition (typically the output of
   * `partitionStages` over the current directory + cert state).
   *
   * Carries forward dispositions already collected at the current
   * stage. Stages strictly below the current stage have already
   * been processed and are not part of the held entry.
   */
  reevaluate(envelopeId: string, newStages: StagedHeldStage[]): void {
    if (envelopeId === "") {
      throw new Error("delivery: reevaluate empty envelope_id");
    }
    const rec = this.heldMap.get(envelopeId);
    if (rec === undefined) {
      throw new EnvelopeNotHeldError(envelopeId);
    }
    if (rec.stages.length === 0) {
      return;
    }
    const currentStage = rec.stages[0]!.stage;
    const priorDispositions = rec.stages[0]!.dispositions;

    const sortedNew = newStages
      .filter((s) => s.stage >= currentStage)
      .sort((a, b) => a.stage - b.stage);

    const rebuilt: StagedHeldStage[] = [];
    for (const s of sortedNew) {
      if (s.pending_device_ids.length === 0) {
        continue;
      }
      rebuilt.push({
        stage: s.stage,
        pending_device_ids: s.pending_device_ids.slice(),
        dispositions:
          s.stage === currentStage ? priorDispositions.slice() : [],
      });
    }
    if (rebuilt.length === 0) {
      // No stages remain - let the next tick detect completion.
      rec.stages = [];
      return;
    }
    rec.stages = rebuilt;
  }

  /** Whether `envelopeId` is currently held. */
  isHeld(envelopeId: string): boolean {
    return this.heldMap.has(envelopeId);
  }

  /** Number of envelopes currently held. */
  size(): number {
    return this.heldMap.size;
  }
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
