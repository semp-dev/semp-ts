/**
 * HTTP/2 transport tests. Cover SSE encode/decode, h2Post
 * (request/response) and dialH2Session (long-lived bidirectional)
 * with a fake fetch.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  type H2FetchLike,
  type H2Response,
  SSEDecoder,
  SempSessionIdHeader,
  decodeSSE,
  dialH2Session,
  encodeSSE,
  h2Post,
} from "./h2.js";

function fakeResponse(opts: {
  status?: number;
  body?: Uint8Array | string;
  headers?: Record<string, string>;
  streamBody?: AsyncIterable<Uint8Array>;
}): H2Response {
  const status = opts.status ?? 200;
  const headers = opts.headers ?? {};
  const buf =
    typeof opts.body === "string"
      ? new TextEncoder().encode(opts.body).buffer
      : opts.body !== undefined
        ? opts.body.buffer
        : new ArrayBuffer(0);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name: string) => {
        const k = name.toLowerCase();
        for (const [hk, hv] of Object.entries(headers)) {
          if (hk.toLowerCase() === k) {
            return hv;
          }
        }
        return null;
      },
    },
    arrayBuffer: async () => buf as ArrayBuffer,
    body: opts.streamBody,
  };
}

async function* sseStream(events: string[]): AsyncIterable<Uint8Array> {
  for (const ev of events) {
    yield new TextEncoder().encode(ev);
  }
}

describe("encodeSSE", () => {
  test("wraps a single-line message", () => {
    expect(encodeSSE('{"type":"X"}')).toBe('data: {"type":"X"}\n\n');
  });

  test("emits one data: per LF-separated line", () => {
    expect(encodeSSE("a\nb")).toBe("data: a\ndata: b\n\n");
  });

  test("collapses CRLF to LF", () => {
    expect(encodeSSE("a\r\nb")).toBe("data: a\ndata: b\n\n");
  });

  test("collapses bare CR to LF", () => {
    expect(encodeSSE("a\rb")).toBe("data: a\ndata: b\n\n");
  });

  test("empty message becomes a single empty data line", () => {
    expect(encodeSSE("")).toBe("data: \n\n");
  });
});

describe("decodeSSE / SSEDecoder", () => {
  test("decodes a single event", () => {
    expect(decodeSSE('data: {"x":1}\n\n')).toEqual(['{"x":1}']);
  });

  test("decodes multiple events", () => {
    const blob =
      'data: {"x":1}\n\n' +
      'data: {"x":2}\n\n' +
      'data: {"x":3}\n\n';
    expect(decodeSSE(blob)).toEqual(['{"x":1}', '{"x":2}', '{"x":3}']);
  });

  test("stitches multi-line data: payloads with LF", () => {
    expect(decodeSSE("data: line1\ndata: line2\n\n")).toEqual(["line1\nline2"]);
  });

  test("ignores comment lines", () => {
    expect(decodeSSE(": keepalive\ndata: ok\n\n")).toEqual(["ok"]);
  });

  test("ignores non-data fields", () => {
    expect(decodeSSE("event: rekey\ndata: ok\nid: 7\n\n")).toEqual(["ok"]);
  });

  test("handles CRLF line endings", () => {
    expect(decodeSSE("data: ok\r\n\r\n")).toEqual(["ok"]);
  });

  test("flushes a trailing event missing the final blank line", () => {
    // The data line terminator is present, but the event-ending blank
    // line is not (server dropped mid-stream). Flush surfaces the
    // pending data lines as one final event.
    const dec = new SSEDecoder();
    dec.push("data: tail\n");
    expect(dec.next()).toBeNull();
    expect(dec.flush()).toBe("tail");
  });

  test("decoder is incremental across pushes", () => {
    const dec = new SSEDecoder();
    dec.push("data: ");
    expect(dec.next()).toBeNull();
    dec.push("hello\n");
    expect(dec.next()).toBeNull();
    dec.push("\n");
    expect(dec.next()).toBe("hello");
  });
});

describe("h2Post", () => {
  test("happy path returns body + sessionId header", async () => {
    const fetchImpl: H2FetchLike = async () =>
      fakeResponse({
        body: '{"step":"response"}',
        headers: { [SempSessionIdHeader]: "01J7SESSION0000000000000" },
      });
    const result = await h2Post(
      "https://example.com/v1/handshake",
      new TextEncoder().encode('{"step":"init"}'),
      { fetchImpl },
    );
    expect(new TextDecoder().decode(result.body)).toBe('{"step":"response"}');
    expect(result.sessionId).toBe("01J7SESSION0000000000000");
    expect(result.status).toBe(200);
  });

  test("forwards Semp-Session-Id on subsequent steps", async () => {
    let observedHeaders: Record<string, string> | undefined;
    const fetchImpl: H2FetchLike = async (_url, init) => {
      observedHeaders = init.headers;
      return fakeResponse({ body: '{"step":"accepted"}' });
    };
    await h2Post(
      "https://example.com/v1/handshake",
      new TextEncoder().encode('{"step":"confirm"}'),
      { fetchImpl, sessionId: "01J7SESSION0000000000000" },
    );
    expect(observedHeaders?.[SempSessionIdHeader]).toBe("01J7SESSION0000000000000");
  });

  test("rejects on 400 with descriptive error", async () => {
    const fetchImpl: H2FetchLike = async () =>
      fakeResponse({ status: 400, body: "bad" });
    await expect(
      h2Post(
        "https://example.com/v1/handshake",
        new TextEncoder().encode("x"),
        { fetchImpl },
      ),
    ).rejects.toThrow(/malformed/);
  });

  test("rejects on 413 / 429 / 503 with structured reason", async () => {
    for (const [status, kind] of [
      [413, /max_envelope_size/],
      [429, /rate limit/],
      [503, /unavailable/],
    ] as Array<[number, RegExp]>) {
      const fetchImpl: H2FetchLike = async () =>
        fakeResponse({ status, body: "x" });
      await expect(
        h2Post(
          "https://example.com/v1/envelope",
          new TextEncoder().encode("x"),
          { fetchImpl },
        ),
      ).rejects.toThrow(kind);
    }
  });

  test("rejects empty url", async () => {
    await expect(h2Post("", new Uint8Array(0))).rejects.toThrow(/empty url/);
  });
});

describe("dialH2Session", () => {
  test("receive yields each SSE event in order", async () => {
    const events = [
      'data: {"type":"SEMP_DELIVERY_EVENT","status":"delivered"}\n\n',
      'data: {"type":"SEMP_REKEY","step":"init"}\n\n',
    ];
    const fetchImpl: H2FetchLike = async () =>
      fakeResponse({ streamBody: sseStream(events) });

    const transport = await dialH2Session({
      sessionUrl: "https://example.com/v1/session/01J",
      fetchImpl,
    });
    const ev1 = await transport.receive();
    const ev2 = await transport.receive();
    expect(ev1).not.toBeNull();
    expect(ev2).not.toBeNull();
    expect(new TextDecoder().decode(ev1 as Uint8Array)).toContain(
      "SEMP_DELIVERY_EVENT",
    );
    expect(new TextDecoder().decode(ev2 as Uint8Array)).toContain("SEMP_REKEY");
    // After EOF: receive returns null.
    const ev3 = await transport.receive();
    expect(ev3).toBeNull();
    await transport.close();
  });

  test("send POSTs to the same session URL", async () => {
    const seen: string[] = [];
    const fetchImpl: H2FetchLike = async (url, init) => {
      seen.push(`${init.method} ${url}`);
      if (init.method === "POST" && (init.headers.Accept ?? "") === "text/event-stream") {
        return fakeResponse({ streamBody: sseStream([]) });
      }
      return fakeResponse({ body: "{}" });
    };
    const url = "https://example.com/v1/session/01J";
    const transport = await dialH2Session({ sessionUrl: url, fetchImpl });
    await transport.send(new TextEncoder().encode('{"type":"X"}'));
    await transport.close();
    expect(seen[0]).toBe(`POST ${url}`); // initial open
    expect(seen[1]).toBe(`POST ${url}`); // subsequent send
  });

  test("send after close throws", async () => {
    const fetchImpl: H2FetchLike = async () =>
      fakeResponse({ streamBody: sseStream([]) });
    const transport = await dialH2Session({
      sessionUrl: "https://example.com/v1/session/01J",
      fetchImpl,
    });
    await transport.close();
    await expect(transport.send(new Uint8Array([1, 2]))).rejects.toThrow(/closed/);
  });

  test("rejects when initial POST returns non-200", async () => {
    const fetchImpl: H2FetchLike = async () =>
      fakeResponse({ status: 503, streamBody: sseStream([]) });
    await expect(
      dialH2Session({
        sessionUrl: "https://example.com/v1/session/01J",
        fetchImpl,
      }),
    ).rejects.toThrow(/unavailable/);
  });

  test("rejects empty sessionUrl", async () => {
    await expect(
      dialH2Session({ sessionUrl: "", fetchImpl: async () => fakeResponse({}) }),
    ).rejects.toThrow(/sessionUrl/);
  });

  test("close is idempotent", async () => {
    const fetchImpl: H2FetchLike = async () =>
      fakeResponse({ streamBody: sseStream([]) });
    const transport = await dialH2Session({
      sessionUrl: "https://example.com/v1/session/01J",
      fetchImpl,
    });
    await transport.close();
    await transport.close();
  });
});
