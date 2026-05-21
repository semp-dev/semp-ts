/**
 * Tests for the sending-side delivery {@link Scheduler}.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type AttemptResult,
  type DeliverFunc,
  InMemorySchedulerStore,
  Scheduler,
  TickInProgressError,
  UnknownRecordError,
} from "./scheduler.js";

describe("Scheduler.enqueue + tick happy path", () => {
  test("delivered attempt -> state=delivered, terminal", async () => {
    const store = new InMemorySchedulerStore();
    let now = new Date("2026-05-08T10:00:00Z");
    const events: string[] = [];
    const deliver: DeliverFunc = async () => ({ status: "delivered" });
    const scheduler = new Scheduler({
      store,
      deliver,
      now: () => now,
      eventSink: (ev) => events.push(`${ev.recipient}:${ev.status}`),
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    const r = await scheduler.tick();
    expect(r.advanced).toBe(1);
    const q = await store.get("env-1", "alice@example.com");
    expect(q?.state).toBe("delivered");
    expect(events).toContain("alice@example.com:delivered");
  });

  test("non-recoverable rejected -> state=rejected", async () => {
    const store = new InMemorySchedulerStore();
    const now = new Date("2026-05-08T10:00:00Z");
    const deliver: DeliverFunc = async () => ({
      status: "rejected",
      reasonCode: "blocked_recipient",
      reason: "blocked",
    });
    const scheduler = new Scheduler({ store, deliver, now: () => now });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    await scheduler.tick();
    const q = await store.get("env-1", "alice@example.com");
    expect(q?.state).toBe("rejected");
  });

  test("silent attempt -> schedules next attempt with backoff", async () => {
    const store = new InMemorySchedulerStore();
    let now = new Date("2026-05-08T10:00:00Z");
    const deliver: DeliverFunc = async () => ({ status: "silent" });
    const scheduler = new Scheduler({
      store,
      deliver,
      now: () => now,
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    await scheduler.tick();
    const q = await store.get("env-1", "alice@example.com");
    expect(q?.state).toBe("queued");
    expect(q?.attempts).toBe(1);
    expect(q?.next_attempt_at).not.toBeNull();
    expect(Date.parse(q!.next_attempt_at!)).toBeGreaterThan(now.getTime());
  });

  test("recoverable rejected retries; expires when next attempt past deadline", async () => {
    const store = new InMemorySchedulerStore();
    let now = new Date("2026-05-08T10:00:00Z");
    let attempt = 0;
    const deliver: DeliverFunc = async () => {
      attempt++;
      return {
        status: "rejected",
        reasonCode: "transient_error",
        reason: "try later",
      };
    };
    void attempt;
    const scheduler = new Scheduler({
      store,
      deliver,
      now: () => now,
      maxRetryHorizonMs: 1, // tiny window so the next attempt lands past deadline.
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date(now.getTime() + 5),
    );
    // First tick attempts and reschedules.
    await scheduler.tick();
    // Move clock past deadline.
    now = new Date(now.getTime() + 60_000);
    await scheduler.tick();
    const q = await store.get("env-1", "alice@example.com");
    expect(q?.state).toBe("expired");
  });
});

describe("Scheduler.cancel", () => {
  test("cancels a queued record", async () => {
    const store = new InMemorySchedulerStore();
    const now = new Date("2026-05-08T10:00:00Z");
    const scheduler = new Scheduler({
      store,
      deliver: async () => ({ status: "silent" }),
      now: () => now,
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    const r = await scheduler.cancel("env-1", "alice@example.com");
    expect(r.state).toBe("canceled");
    const q = await store.get("env-1", "alice@example.com");
    expect(q?.state).toBe("canceled");
  });

  test("cancellation of an already-terminal record is a no-op", async () => {
    const store = new InMemorySchedulerStore();
    const now = new Date("2026-05-08T10:00:00Z");
    const scheduler = new Scheduler({
      store,
      deliver: async () => ({ status: "delivered" }),
      now: () => now,
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    await scheduler.tick();
    const r = await scheduler.cancel("env-1", "alice@example.com");
    expect(r.state).toBe("delivered");
    expect(r.reason).toMatch(/no-op/);
  });

  test("cancel of unknown record throws", async () => {
    const store = new InMemorySchedulerStore();
    const scheduler = new Scheduler({
      store,
      deliver: async () => ({ status: "silent" }),
    });
    await expect(
      scheduler.cancel("missing", "alice@example.com"),
    ).rejects.toThrow(UnknownRecordError);
  });
});

describe("Scheduler.cancelEnvelope", () => {
  test("cancels every recipient still non-terminal", async () => {
    const store = new InMemorySchedulerStore();
    const now = new Date("2026-05-08T10:00:00Z");
    const scheduler = new Scheduler({
      store,
      deliver: async () => ({ status: "silent" }),
      now: () => now,
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    await scheduler.enqueue(
      "env-1",
      "bob@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    const out = await scheduler.cancelEnvelope("env-1");
    expect(out.map((r) => r.state).sort()).toEqual(["canceled", "canceled"]);
  });
});

describe("Scheduler.tick concurrency", () => {
  test("concurrent tick is rejected", async () => {
    const store = new InMemorySchedulerStore();
    let inflight = 0;
    const deliver: DeliverFunc = async () => {
      inflight++;
      // Park here long enough for the second tick to race.
      await new Promise((r) => setTimeout(r, 5));
      inflight--;
      return { status: "silent" };
    };
    const scheduler = new Scheduler({
      store,
      deliver,
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date(Date.now() + 60_000),
    );
    const a = scheduler.tick();
    let raced = false;
    try {
      await scheduler.tick();
    } catch (err) {
      raced = err instanceof TickInProgressError;
    }
    await a;
    expect(raced).toBe(true);
    void inflight;
  });
});

describe("Scheduler.pruneTerminal", () => {
  test("removes terminal records past retention", async () => {
    const store = new InMemorySchedulerStore();
    let now = new Date("2026-05-08T10:00:00Z");
    const scheduler = new Scheduler({
      store,
      deliver: async () => ({ status: "delivered" }),
      now: () => now,
    });
    await scheduler.enqueue(
      "env-1",
      "alice@example.com",
      new Date("2027-01-01T00:00:00Z"),
    );
    await scheduler.tick();
    // Advance past 7 days.
    now = new Date(now.getTime() + 8 * 24 * 3_600_000);
    const pruned = await scheduler.pruneTerminal(7 * 24 * 3_600_000);
    expect(pruned).toBe(1);
    expect(await store.get("env-1", "alice@example.com")).toBeNull();
  });
});

describe("Scheduler input validation", () => {
  test("enqueue rejects empty envelope_id / recipient", async () => {
    const store = new InMemorySchedulerStore();
    const scheduler = new Scheduler({
      store,
      deliver: async () => {
        const r: AttemptResult = { status: "delivered" };
        return r;
      },
    });
    await expect(
      scheduler.enqueue("", "alice", new Date("2027-01-01")),
    ).rejects.toThrow(/envelope_id/);
    await expect(
      scheduler.enqueue("env-1", "", new Date("2027-01-01")),
    ).rejects.toThrow(/recipient/);
  });

  test("enqueue rejects duplicate", async () => {
    const store = new InMemorySchedulerStore();
    const scheduler = new Scheduler({
      store,
      deliver: async () => ({ status: "delivered" }),
    });
    await scheduler.enqueue(
      "env-1",
      "alice",
      new Date("2027-01-01T00:00:00Z"),
    );
    await expect(
      scheduler.enqueue("env-1", "alice", new Date("2027-01-01T00:00:00Z")),
    ).rejects.toThrow(/already exists/);
  });
});
