/**
 * Tests for SEMP_KEYS request / response wire shape and the fetchKeys
 * client helper.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type KeysClientStream,
  type KeysResponse,
  KeysRequestType,
  KeysRequestVersion,
  fetchKeys,
  newKeysRequest,
  newKeysResponse,
  validateKeysRequest,
} from "./request.js";

describe("newKeysRequest / validateKeysRequest", () => {
  test("populates version, timestamp, and include_domain_keys=true", () => {
    const r = newKeysRequest(
      "01JREQ00000000000000000000",
      ["alice@example.com", "bob@example.com"],
      () => new Date("2026-05-08T10:00:00Z"),
    );
    expect(r.type).toBe(KeysRequestType);
    expect(r.step).toBe("request");
    expect(r.version).toBe(KeysRequestVersion);
    expect(r.id).toBe("01JREQ00000000000000000000");
    expect(r.timestamp).toBe("2026-05-08T10:00:00Z");
    expect(r.addresses).toEqual(["alice@example.com", "bob@example.com"]);
    expect(r.include_domain_keys).toBe(true);
    expect(() => validateKeysRequest(r)).not.toThrow();
  });

  test("rejects empty id", () => {
    expect(() => newKeysRequest("", ["alice@example.com"])).toThrow(
      /empty request id/,
    );
  });

  test("rejects empty addresses", () => {
    expect(() => newKeysRequest("01JREQ", [])).toThrow(
      /at least one address/,
    );
  });

  test("validateKeysRequest catches malformed timestamp", () => {
    const r = newKeysRequest("01JREQ", ["a@b.com"]);
    r.timestamp = "not-a-date";
    expect(() => validateKeysRequest(r)).toThrow(/ISO 8601/);
  });

  test("validateKeysRequest catches missing addresses element", () => {
    const r = newKeysRequest("01JREQ", ["a@b.com"]);
    r.addresses = ["a@b.com", ""];
    expect(() => validateKeysRequest(r)).toThrow(/addresses\[1\]/);
  });

  test("validateKeysRequest requires include_domain_keys to be boolean", () => {
    const r = newKeysRequest("01JREQ", ["a@b.com"]);
    (r as unknown as Record<string, unknown>).include_domain_keys = "yes";
    expect(() => validateKeysRequest(r)).toThrow(/include_domain_keys/);
  });
});

describe("newKeysResponse", () => {
  test("echoes request id and stamps timestamp", () => {
    const resp = newKeysResponse(
      "01JREQ",
      [
        {
          address: "alice@example.com",
          status: "found",
          domain: "example.com",
          user_keys: [],
        },
      ],
      () => new Date("2026-05-08T10:00:01Z"),
    );
    expect(resp.id).toBe("01JREQ");
    expect(resp.step).toBe("response");
    expect(resp.timestamp).toBe("2026-05-08T10:00:01Z");
    expect(resp.results).toHaveLength(1);
  });

  test("rejects empty request id", () => {
    expect(() => newKeysResponse("", [])).toThrow(/empty request id/);
  });
});

describe("fetchKeys", () => {
  /**
   * Build a fake stream that records the bytes the client sent and
   * answers with `respJSON` on the first receive.
   */
  function makeStream(respJSON: unknown): {
    stream: KeysClientStream;
    sent: Uint8Array[];
  } {
    const sent: Uint8Array[] = [];
    let answered = false;
    const stream: KeysClientStream = {
      async send(message) {
        sent.push(message);
      },
      async receive() {
        if (answered) {
          return null;
        }
        answered = true;
        return new TextEncoder().encode(JSON.stringify(respJSON));
      },
    };
    return { stream, sent };
  }

  test("happy path: serializes request, parses response, returns it", async () => {
    const req = newKeysRequest("01JABC", ["alice@example.com"]);
    const fake: KeysResponse = {
      type: KeysRequestType,
      step: "response",
      version: KeysRequestVersion,
      id: "01JABC",
      timestamp: "2026-05-08T10:00:00Z",
      results: [
        {
          address: "alice@example.com",
          status: "found",
          domain: "example.com",
          user_keys: [],
        },
      ],
    };
    const { stream, sent } = makeStream(fake);
    const resp = await fetchKeys(stream, req);
    expect(resp.id).toBe("01JABC");
    expect(resp.results[0]!.address).toBe("alice@example.com");
    // The request bytes that landed on the wire round-trip back to req.
    const wire = JSON.parse(new TextDecoder().decode(sent[0]!));
    expect(wire).toMatchObject({ type: KeysRequestType, id: "01JABC" });
  });

  test("rejects response with mismatched id", async () => {
    const req = newKeysRequest("01JABC", ["alice@example.com"]);
    const fake = {
      type: KeysRequestType,
      step: "response",
      version: KeysRequestVersion,
      id: "01JOTHER",
      timestamp: "2026-05-08T10:00:00Z",
      results: [],
    };
    const { stream } = makeStream(fake);
    await expect(fetchKeys(stream, req)).rejects.toThrow(/does not match/);
  });

  test("rejects non-SEMP_KEYS response", async () => {
    const req = newKeysRequest("01JABC", ["a@b.com"]);
    const fake = {
      type: "SEMP_OTHER",
      step: "response",
      version: KeysRequestVersion,
      id: "01JABC",
      timestamp: "2026-05-08T10:00:00Z",
      results: [],
    };
    const { stream } = makeStream(fake);
    await expect(fetchKeys(stream, req)).rejects.toThrow(/response type/);
  });

  test("rejects connection close before response", async () => {
    const req = newKeysRequest("01JABC", ["a@b.com"]);
    const stream: KeysClientStream = {
      async send() {},
      async receive() {
        return null;
      },
    };
    await expect(fetchKeys(stream, req)).rejects.toThrow(
      /connection closed/,
    );
  });
});
