/**
 * Delivery extras tests: retry, queue state, block list match.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type BlockList,
  type QueueState,
  DefaultMaxRetryHorizonMs,
  MaxRetryHorizonCapMs,
  MaxRetryIntervalMs,
  MinJitterFloorMs,
  MinRetryAttempts,
  MinRetryInitialIntervalMs,
  MinRetryJitterFraction,
  MinRetryMultiplier,
  StaticBlockListLookup,
  baseIntervalMs,
  effectiveDeadline,
  isRecoverableReason,
  isTerminalState,
  jitterIntervalMs,
  matchBlockList,
  nextAttemptAt,
  sanitizeRetry,
  setTerminal,
} from "./index.js";

describe("retry: sanitizeRetry", () => {
  test("zero values clamp to spec minima", () => {
    const eff = sanitizeRetry({});
    expect(eff.initialIntervalMs).toBe(MinRetryInitialIntervalMs);
    expect(eff.multiplier).toBe(MinRetryMultiplier);
    expect(eff.maxIntervalMs).toBe(MaxRetryIntervalMs);
    expect(eff.jitterFraction).toBe(MinRetryJitterFraction);
  });

  test("below-minimum values clamp up", () => {
    const eff = sanitizeRetry({
      initialIntervalMs: 1,
      multiplier: 1,
      maxIntervalMs: -1,
      jitterFraction: 0.05,
    });
    expect(eff.initialIntervalMs).toBe(MinRetryInitialIntervalMs);
    expect(eff.multiplier).toBe(MinRetryMultiplier);
    expect(eff.maxIntervalMs).toBe(MaxRetryIntervalMs);
    expect(eff.jitterFraction).toBe(MinRetryJitterFraction);
  });

  test("above-cap maxInterval clamps down", () => {
    const eff = sanitizeRetry({ maxIntervalMs: MaxRetryIntervalMs * 2 });
    expect(eff.maxIntervalMs).toBe(MaxRetryIntervalMs);
  });
});

describe("retry: baseIntervalMs", () => {
  test("attempt=0 returns initial interval", () => {
    expect(baseIntervalMs({}, 0)).toBe(MinRetryInitialIntervalMs);
  });

  test("attempt=N grows by multiplier^N", () => {
    expect(baseIntervalMs({}, 1)).toBe(MinRetryInitialIntervalMs * 2);
    expect(baseIntervalMs({}, 2)).toBe(MinRetryInitialIntervalMs * 4);
    expect(baseIntervalMs({}, 3)).toBe(MinRetryInitialIntervalMs * 8);
  });

  test("clamps to maxIntervalMs", () => {
    expect(baseIntervalMs({}, 100)).toBe(MaxRetryIntervalMs);
  });
});

describe("retry: jitterIntervalMs", () => {
  test("scales by [1-j, 1+j] from random in [0, 1)", () => {
    const cfg = { jitterFraction: 0.5 };
    expect(jitterIntervalMs(cfg, 60_000, () => 0)).toBe(
      Math.max(MinJitterFloorMs, Math.floor(60_000 * 0.5)),
    );
    // r=0.999... ≈ 1+j
    expect(jitterIntervalMs(cfg, 60_000, () => 0.9999999)).toBe(
      Math.floor(60_000 * 1.4999999),
    );
  });

  test("respects MinJitterFloorMs floor", () => {
    expect(jitterIntervalMs({ jitterFraction: 0.99 }, 1000, () => 0)).toBe(
      MinJitterFloorMs,
    );
  });

  test("rejects non-positive base", () => {
    expect(() => jitterIntervalMs({}, 0, () => 0.5)).toThrow(/non-positive/);
  });

  test("rejects out-of-range random", () => {
    expect(() => jitterIntervalMs({}, 60_000, () => 1.5)).toThrow(
      /out-of-range/,
    );
  });
});

describe("retry: nextAttemptAt", () => {
  test("returns previous + jittered base", () => {
    const previous = new Date("2026-04-21T10:00:00Z");
    const next = nextAttemptAt({}, previous, 0, () => 0.5);
    // r=0.5 -> multiplier=1 -> exact base interval = 60s.
    expect(next.getTime() - previous.getTime()).toBe(60_000);
  });

  test("rejects invalid previous", () => {
    expect(() =>
      nextAttemptAt({}, new Date(NaN), 0, () => 0.5),
    ).toThrow(/invalid/);
  });
});

describe("retry: isRecoverableReason", () => {
  test("§2.3 recoverable codes return true", () => {
    for (const c of [
      "handshake_invalid",
      "handshake_expired",
      "no_session",
      "server_unavailable",
      "rate_limited",
      "server_at_capacity",
    ]) {
      expect(isRecoverableReason(c)).toBe(true);
    }
  });

  test("non-recoverable codes return false", () => {
    for (const c of ["seal_invalid", "policy_forbidden", "envelope_expired"]) {
      expect(isRecoverableReason(c)).toBe(false);
    }
  });

  test("MinRetryAttempts is 5 per §2.3", () => {
    expect(MinRetryAttempts).toBe(5);
  });
});

describe("retry: effectiveDeadline", () => {
  test("returns earlier of postmark.expires and queuedAt+horizon", () => {
    const queuedAt = new Date("2026-04-21T10:00:00Z");
    const horizon = 60 * 60 * 1000; // 1h
    const farExpires = new Date("2026-04-25T10:00:00Z");
    const sooner = new Date("2026-04-21T10:30:00Z");

    expect(effectiveDeadline(farExpires, queuedAt, horizon).toISOString()).toBe(
      new Date(queuedAt.getTime() + horizon).toISOString(),
    );
    expect(effectiveDeadline(sooner, queuedAt, horizon).toISOString()).toBe(
      sooner.toISOString(),
    );
  });

  test("zero horizon defaults to DefaultMaxRetryHorizonMs", () => {
    const queuedAt = new Date("2026-04-21T10:00:00Z");
    expect(
      effectiveDeadline(null, queuedAt, 0).getTime() - queuedAt.getTime(),
    ).toBe(DefaultMaxRetryHorizonMs);
  });

  test("horizon above cap clamps to MaxRetryHorizonCapMs", () => {
    const queuedAt = new Date("2026-04-21T10:00:00Z");
    expect(
      effectiveDeadline(null, queuedAt, 30 * 24 * 3600 * 1000).getTime() -
        queuedAt.getTime(),
    ).toBe(MaxRetryHorizonCapMs);
  });
});

describe("queue: setTerminal + isTerminalState", () => {
  test("transitions to terminal state and stamps terminal_at", () => {
    const q: QueueState = {
      envelope_id: "env-1",
      recipient: "bob@x",
      state: "queued",
      attempts: 1,
      last_attempt_at: null,
      last_outcome: null,
      last_reason_code: null,
      next_attempt_at: "2026-04-21T11:00:00Z",
      deadline: "2026-04-22T10:00:00Z",
    };
    setTerminal(q, "delivered", new Date("2026-04-21T10:30:00Z"));
    expect(q.state).toBe("delivered");
    expect(q.next_attempt_at).toBeNull();
    expect(q.terminal_at).toBe("2026-04-21T10:30:00Z");
  });

  test("idempotent on already-terminal record", () => {
    const q: QueueState = {
      envelope_id: "env-1",
      recipient: "bob@x",
      state: "delivered",
      attempts: 1,
      last_attempt_at: null,
      last_outcome: null,
      last_reason_code: null,
      next_attempt_at: null,
      deadline: "2026-04-22T10:00:00Z",
      terminal_at: "2026-04-21T10:30:00Z",
    };
    setTerminal(q, "rejected", new Date("2026-04-21T11:00:00Z"));
    expect(q.state).toBe("delivered");
    expect(q.terminal_at).toBe("2026-04-21T10:30:00Z");
  });

  test("ignores non-terminal target state", () => {
    const q: QueueState = {
      envelope_id: "env-1",
      recipient: "bob@x",
      state: "queued",
      attempts: 1,
      last_attempt_at: null,
      last_outcome: null,
      last_reason_code: null,
      next_attempt_at: null,
      deadline: "2026-04-22T10:00:00Z",
    };
    setTerminal(q, "queued", new Date());
    expect(q.state).toBe("queued");
    expect(q.terminal_at).toBeUndefined();
  });

  test("isTerminalState classifies the five states", () => {
    expect(isTerminalState("queued")).toBe(false);
    expect(isTerminalState("delivered")).toBe(true);
    expect(isTerminalState("rejected")).toBe(true);
    expect(isTerminalState("expired")).toBe(true);
    expect(isTerminalState("canceled")).toBe(true);
  });
});

describe("blocklist: matchBlockList precedence", () => {
  function listOf(entries: BlockList["entries"]): BlockList {
    return { user_id: "alice@example.com", list_version: 1, entries };
  }

  test("user > server > domain", () => {
    const list = listOf([
      {
        id: "1",
        entity: { type: "domain", domain: "evil.example" },
        acknowledgment: "rejected",
        scope: "all",
        created_at: "2026-04-01T00:00:00Z",
        created_by_device_id: "dev-1",
      },
      {
        id: "2",
        entity: { type: "user", address: "spammer@evil.example" },
        acknowledgment: "silent",
        scope: "all",
        created_at: "2026-04-01T00:00:00Z",
        created_by_device_id: "dev-1",
      },
    ]);
    const match = matchBlockList(list, {
      address: "spammer@evil.example",
      domain: "evil.example",
    });
    expect(match?.id).toBe("2");
    expect(match?.acknowledgment).toBe("silent");
  });

  test("expired entries are skipped", () => {
    const list = listOf([
      {
        id: "1",
        entity: { type: "user", address: "old@example.com" },
        acknowledgment: "rejected",
        scope: "all",
        created_at: "2026-04-01T00:00:00Z",
        expires_at: "2026-04-15T00:00:00Z",
        created_by_device_id: "dev-1",
      },
    ]);
    const now = new Date("2026-04-21T10:00:00Z");
    expect(matchBlockList(list, { address: "old@example.com" }, now)).toBeNull();
  });

  test("scope=direct matches non-group; scope=group matches group", () => {
    const list = listOf([
      {
        id: "d",
        entity: { type: "user", address: "x@y" },
        acknowledgment: "rejected",
        scope: "direct",
        created_at: "2026-04-01T00:00:00Z",
        created_by_device_id: "dev-1",
      },
      {
        id: "g",
        entity: { type: "user", address: "x@y" },
        acknowledgment: "silent",
        scope: "group",
        created_at: "2026-04-01T00:00:00Z",
        created_by_device_id: "dev-1",
      },
    ]);
    const direct = matchBlockList(list, { address: "x@y", isGroup: false });
    const group = matchBlockList(list, { address: "x@y", isGroup: true });
    expect(direct?.id).toBe("d");
    expect(group?.id).toBe("g");
  });

  test("case-insensitive comparison", () => {
    const list = listOf([
      {
        id: "1",
        entity: { type: "domain", domain: "example.com" },
        acknowledgment: "rejected",
        scope: "all",
        created_at: "2026-04-01T00:00:00Z",
        created_by_device_id: "dev-1",
      },
    ]);
    expect(
      matchBlockList(list, { domain: "EXAMPLE.COM" })?.id,
    ).toBe("1");
  });

  test("null list returns null", () => {
    expect(matchBlockList(null, { address: "x@y" })).toBeNull();
  });

  test("StaticBlockListLookup case-insensitive recipient lookup", async () => {
    const list = listOf([
      {
        id: "1",
        entity: { type: "user", address: "x@y" },
        acknowledgment: "rejected",
        scope: "all",
        created_at: "2026-04-01T00:00:00Z",
        created_by_device_id: "dev-1",
      },
    ]);
    const lookup = new StaticBlockListLookup({
      "alice@example.com": list,
    });
    expect(await lookup.lookup("Alice@Example.COM")).toBe(list);
    expect(await lookup.lookup("ghost@example.com")).toBeNull();
  });
});
