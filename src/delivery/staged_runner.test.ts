/**
 * Tests for the {@link StagedRunner} staged-delivery runtime per
 * DELIVERY.md §3.2.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  EnvelopeAlreadyHeldError,
  EnvelopeNotHeldError,
  StagedRunner,
} from "./staged_runner.js";
import {
  type Disposition,
  type StagedHeldStage,
} from "./disposition.js";

function emptyStage(stage: number, devs: string[]): StagedHeldStage {
  return {
    stage,
    pending_device_ids: devs.slice(),
    dispositions: [],
  };
}

function makeRunner(opts: {
  stageTimeoutMs?: number;
  now?: () => Date;
} = {}) {
  const events: string[] = [];
  const runner = new StagedRunner({
    deliver: async (envId, stage, devs) => {
      events.push(`deliver:${envId}:${stage}:${devs.join(",")}`);
    },
    suppress: async (envId, stage) => {
      events.push(`suppress:${envId}:${stage}`);
    },
    complete: async (envId) => {
      events.push(`complete:${envId}`);
    },
    ...(opts.stageTimeoutMs !== undefined ? { stageTimeoutMs: opts.stageTimeoutMs } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
  });
  return { runner, events };
}

describe("StagedRunner", () => {
  test("hold delivers to lowest stage immediately", async () => {
    const { runner, events } = makeRunner();
    await runner.hold("env-1", [emptyStage(1, ["d1", "d2"])]);
    expect(events).toEqual(["deliver:env-1:1:d1,d2"]);
    expect(runner.isHeld("env-1")).toBe(true);
  });

  test("rejects empty partition", async () => {
    const { runner } = makeRunner();
    await expect(runner.hold("env-1", [])).rejects.toThrow(/no pending devices/);
  });

  test("rejects non-monotonic stages", async () => {
    const { runner } = makeRunner();
    await expect(
      runner.hold("env-1", [
        emptyStage(2, ["d1"]),
        emptyStage(1, ["d2"]),
      ]),
    ).rejects.toThrow(/not monotonically increasing/);
  });

  test("duplicate hold throws EnvelopeAlreadyHeldError", async () => {
    const { runner } = makeRunner();
    await runner.hold("env-1", [emptyStage(1, ["d1"])]);
    await expect(runner.hold("env-1", [emptyStage(1, ["d2"])])).rejects.toThrow(
      EnvelopeAlreadyHeldError,
    );
  });

  test("ingest + tick advances when every device emits advance", async () => {
    const { runner, events } = makeRunner();
    await runner.hold("env-1", [
      emptyStage(1, ["d1", "d2"]),
      emptyStage(2, ["d3"]),
    ]);
    runner.ingestDisposition("env-1", "d1", makeDisposition("d1", "advance"));
    runner.ingestDisposition("env-1", "d2", makeDisposition("d2", "advance"));
    const r = await runner.tick();
    expect(r.advanced).toBe(1);
    expect(events).toEqual([
      "deliver:env-1:1:d1,d2",
      "deliver:env-1:2:d3",
    ]);
  });

  test("any suppress at a stage suppresses the envelope", async () => {
    const { runner, events } = makeRunner();
    await runner.hold("env-1", [emptyStage(1, ["d1", "d2"])]);
    runner.ingestDisposition("env-1", "d1", makeDisposition("d1", "advance"));
    runner.ingestDisposition("env-1", "d2", makeDisposition("d2", "suppress"));
    await runner.tick();
    expect(events).toContain("suppress:env-1:1");
    expect(runner.isHeld("env-1")).toBe(false);
  });

  test("all stages advance → complete", async () => {
    const { runner, events } = makeRunner();
    await runner.hold("env-1", [emptyStage(1, ["d1"])]);
    runner.ingestDisposition("env-1", "d1", makeDisposition("d1", "advance"));
    await runner.tick();
    expect(events).toContain("complete:env-1");
    expect(runner.isHeld("env-1")).toBe(false);
  });

  test("deadline elapsed → advance with empty dispositions (fail-open per §3.2.4)", async () => {
    let now = new Date("2026-05-08T10:00:00Z");
    const { runner, events } = makeRunner({
      stageTimeoutMs: 1_000,
      now: () => now,
    });
    await runner.hold("env-1", [
      emptyStage(1, ["d1"]),
      emptyStage(2, ["d2"]),
    ]);
    // Move the clock past the deadline without any disposition.
    now = new Date("2026-05-08T10:00:02Z");
    await runner.tick();
    expect(events).toContain("deliver:env-1:2:d2");
  });

  test("ingest from device not in current stage rejected", async () => {
    const { runner } = makeRunner();
    await runner.hold("env-1", [emptyStage(1, ["d1"])]);
    expect(() =>
      runner.ingestDisposition(
        "env-1",
        "intruder",
        makeDisposition("intruder", "suppress"),
      ),
    ).toThrow(/not in current stage/);
  });

  test("ingest with mismatched submitter rejected", async () => {
    const { runner } = makeRunner();
    await runner.hold("env-1", [emptyStage(1, ["d1"])]);
    expect(() =>
      runner.ingestDisposition(
        "env-1",
        "d2",
        makeDisposition("d1", "advance"),
      ),
    ).toThrow(/does not match disposition device_id/);
  });

  test("repeat ingest is idempotent (keeps first vote)", async () => {
    const { runner, events } = makeRunner();
    await runner.hold("env-1", [emptyStage(1, ["d1"])]);
    runner.ingestDisposition("env-1", "d1", makeDisposition("d1", "advance"));
    runner.ingestDisposition("env-1", "d1", makeDisposition("d1", "suppress"));
    await runner.tick();
    expect(events).toContain("complete:env-1");
  });

  test("reevaluate carries forward dispositions at current stage", async () => {
    const { runner } = makeRunner();
    await runner.hold("env-1", [
      emptyStage(1, ["d1", "d2"]),
      emptyStage(2, ["d3"]),
    ]);
    runner.ingestDisposition("env-1", "d1", makeDisposition("d1", "advance"));
    // Reevaluate: d2 dropped, d4 added at stage 1.
    runner.reevaluate("env-1", [
      emptyStage(1, ["d1", "d4"]),
      emptyStage(2, ["d3"]),
    ]);
    runner.ingestDisposition("env-1", "d4", makeDisposition("d4", "advance"));
    const r = await runner.tick();
    expect(r.advanced).toBe(1);
  });

  test("reevaluate on unknown envelope throws EnvelopeNotHeldError", () => {
    const { runner } = makeRunner();
    expect(() =>
      runner.reevaluate("missing", [emptyStage(1, ["d1"])]),
    ).toThrow(EnvelopeNotHeldError);
  });
});

function makeDisposition(
  deviceId: string,
  decision: "advance" | "suppress",
): Disposition {
  return {
    kind: "delivery-disposition",
    source_envelope_id: "env-1",
    disposition: decision,
    device_id: deviceId,
  };
}
