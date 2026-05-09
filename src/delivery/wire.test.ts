/**
 * Tests for the SEMP_SUBMISSION / cancel / fetch / inbox /
 * internal-route wire types and the disposition primitives.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  DefaultStageTimeoutMs,
  type StagedHeldStage,
  aggregateDispositions,
  isStageComplete,
  validateDisposition,
} from "./disposition.js";
import { Inbox } from "./inbox.js";
import {
  newCancelRequest,
  newCancelResponse,
} from "./cancel.js";
import {
  FetchType,
  FetchVersion,
  newFetchRequest,
  newFetchResponse,
} from "./fetch.js";
import {
  InternalRouteType,
  InternalRouteVersion,
  InternalRouteTimeoutMs,
} from "./internalroute.js";
import {
  SubmissionType,
  newSubmissionEvent,
  newSubmissionResponse,
} from "./submission.js";

describe("submission wire types", () => {
  test("newSubmissionResponse populates type/step/version + timestamp", () => {
    const r = newSubmissionResponse(
      "01JENV",
      [
        {
          recipient: "alice@example.com",
          status: "delivered",
        },
      ],
      () => new Date("2026-05-08T10:00:00Z"),
    );
    expect(r.type).toBe(SubmissionType);
    expect(r.step).toBe("response");
    expect(r.envelope_id).toBe("01JENV");
    expect(r.timestamp).toBe("2026-05-08T10:00:00Z");
  });

  test("newSubmissionEvent rejects empty fields", () => {
    expect(() =>
      newSubmissionEvent("", "alice@example.com", "delivered"),
    ).toThrow(/envelope_id/);
    expect(() => newSubmissionEvent("01JENV", "", "delivered")).toThrow(
      /recipient/,
    );
  });

  test("newSubmissionEvent carries optional reason", () => {
    const ev = newSubmissionEvent("01JENV", "alice@example.com", "rejected", {
      reason_code: "blocked_recipient",
      reason: "blocked by recipient",
      nowFn: () => new Date("2026-05-08T10:00:00Z"),
    });
    expect(ev.reason_code).toBe("blocked_recipient");
    expect(ev.reason).toBe("blocked by recipient");
  });
});

describe("cancel wire types", () => {
  test("newCancelRequest with whole-envelope (no recipient)", () => {
    const r = newCancelRequest("01JENV", {
      nowFn: () => new Date("2026-05-08T10:00:00Z"),
    });
    expect(r.step).toBe("cancel");
    expect(r.envelope_id).toBe("01JENV");
    expect(r.recipient).toBeUndefined();
  });

  test("newCancelRequest with explicit recipient", () => {
    const r = newCancelRequest("01JENV", { recipient: "alice@example.com" });
    expect(r.recipient).toBe("alice@example.com");
  });

  test("newCancelResponse is per-record", () => {
    const r = newCancelResponse("01JENV", [
      { recipient: "alice@example.com", state: "canceled" },
      {
        recipient: "bob@example.com",
        state: "delivered",
        reason: "already delivered, cancellation no-op per §2.7.4",
      },
    ]);
    expect(r.results).toHaveLength(2);
    expect(r.results[1]!.reason).toContain("already delivered");
  });
});

describe("fetch wire types", () => {
  test("newFetchRequest is a tiny constant", () => {
    const r = newFetchRequest();
    expect(r).toEqual({
      type: FetchType,
      step: "request",
      version: FetchVersion,
    });
  });

  test("newFetchResponse defaults drained=true", () => {
    const r = newFetchResponse(["env1-b64"], () => new Date("2026-01-01T00:00:00Z"));
    expect(r.drained).toBe(true);
    expect(r.envelopes).toEqual(["env1-b64"]);
  });
});

describe("Inbox", () => {
  test("store + drain round-trips", () => {
    const ib = new Inbox();
    ib.store("alice@example.com", new Uint8Array([1, 2, 3]));
    ib.store("alice@example.com", new Uint8Array([4, 5, 6]));
    expect(ib.pending("alice@example.com")).toBe(2);
    const out = ib.drain("alice@example.com");
    expect(out).toHaveLength(2);
    expect(Array.from(out[0]!)).toEqual([1, 2, 3]);
    expect(ib.pending("alice@example.com")).toBe(0);
  });

  test("store copies the buffer (caller mutation is not reflected)", () => {
    const ib = new Inbox();
    const buf = new Uint8Array([9, 9, 9]);
    ib.store("a@b.com", buf);
    buf[0] = 0;
    const out = ib.drain("a@b.com");
    expect(Array.from(out[0]!)).toEqual([9, 9, 9]);
  });

  test("respects max queue depth (oldest dropped)", () => {
    const ib = new Inbox(2);
    ib.store("a@b.com", new Uint8Array([1]));
    ib.store("a@b.com", new Uint8Array([2]));
    ib.store("a@b.com", new Uint8Array([3]));
    const out = ib.drain("a@b.com");
    expect(out.map((b) => b[0])).toEqual([2, 3]);
  });
});

describe("internalroute constants", () => {
  test("default timeout is 30s", () => {
    expect(InternalRouteTimeoutMs).toBe(30_000);
    expect(InternalRouteType).toBe("SEMP_INTERNAL_ROUTE");
    expect(InternalRouteVersion).toBe("1.0.0");
  });
});

describe("disposition primitives", () => {
  test("validateDisposition catches missing fields", () => {
    expect(() =>
      validateDisposition({
        kind: "delivery-disposition",
        source_envelope_id: "",
        disposition: "advance",
        device_id: "d-1",
      }),
    ).toThrow(/source_envelope_id/);
    expect(() =>
      validateDisposition({
        kind: "delivery-disposition",
        source_envelope_id: "env",
        disposition: "advance",
        device_id: "",
      }),
    ).toThrow(/device_id/);
    expect(() =>
      validateDisposition({
        kind: "delivery-disposition",
        source_envelope_id: "env",
        disposition: "bogus" as "advance",
        device_id: "d-1",
      }),
    ).toThrow(/not a valid value/);
  });

  test("aggregateDispositions: any suppress wins", () => {
    expect(
      aggregateDispositions([
        {
          kind: "delivery-disposition",
          source_envelope_id: "env",
          disposition: "advance",
          device_id: "d1",
        },
        {
          kind: "delivery-disposition",
          source_envelope_id: "env",
          disposition: "suppress",
          device_id: "d2",
        },
      ]),
    ).toBe("suppress");
  });

  test("aggregateDispositions: empty (timeout) → advance per §3.2.4", () => {
    expect(aggregateDispositions([])).toBe("advance");
  });

  test("isStageComplete: all devices represented", () => {
    const stage: StagedHeldStage = {
      stage: 1,
      pending_device_ids: ["d1", "d2"],
      dispositions: [
        {
          kind: "delivery-disposition",
          source_envelope_id: "env",
          disposition: "advance",
          device_id: "d1",
        },
        {
          kind: "delivery-disposition",
          source_envelope_id: "env",
          disposition: "advance",
          device_id: "d2",
        },
      ],
    };
    expect(isStageComplete(stage, new Date("2026-05-08T10:00:00Z"), "")).toBe(
      true,
    );
  });

  test("isStageComplete: missing one disposition → not complete", () => {
    const stage: StagedHeldStage = {
      stage: 1,
      pending_device_ids: ["d1", "d2"],
      dispositions: [
        {
          kind: "delivery-disposition",
          source_envelope_id: "env",
          disposition: "advance",
          device_id: "d1",
        },
      ],
    };
    expect(isStageComplete(stage, new Date("2026-05-08T10:00:00Z"), "")).toBe(
      false,
    );
  });

  test("isStageComplete: deadline elapsed", () => {
    const stage: StagedHeldStage = {
      stage: 1,
      pending_device_ids: ["d1"],
      dispositions: [],
    };
    expect(
      isStageComplete(
        stage,
        new Date("2026-05-08T10:01:00Z"),
        "2026-05-08T10:00:30Z",
      ),
    ).toBe(true);
    expect(
      isStageComplete(
        stage,
        new Date("2026-05-08T10:00:00Z"),
        "2026-05-08T10:00:30Z",
      ),
    ).toBe(false);
  });

  test("DefaultStageTimeoutMs is 30s", () => {
    expect(DefaultStageTimeoutMs).toBe(30_000);
  });
});
