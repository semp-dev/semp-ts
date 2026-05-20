/**
 * HTTP/2 transport binding per TRANSPORT.md §4.2.
 *
 * Unlike WebSocket, which gives us a single bidirectional pipe,
 * the SEMP HTTP/2 binding is a collection of HTTP endpoints with
 * path-based routing:
 *
 *  - `GET  /v1/discovery/{address}` - discovery lookup (preferred)
 *  - `POST /v1/discovery/{address}` - same lookup with a signed body
 *  - `GET  /v1/keys/{address}`      - key request (preferred)
 *  - `POST /v1/keys/{address}`      - same lookup with a signed body
 *  - `POST /v1/handshake`           - handshake step
 *  - `POST /v1/envelope`            - envelope submit
 *  - `GET  /v1/session/{id}`        - long-lived server-push stream
 *                                     (Server-Sent Events)
 *
 * This module exposes:
 *
 *  - {@link h2Post}: a typed JSON POST helper for the four
 *    request/response endpoints. Surfaces the `Semp-Session-Id`
 *    response header to the caller.
 *  - {@link dialH2Session}: opens a long-lived POST to
 *    `/v1/session/{id}` and returns a {@link Transport} whose
 *    `receive()` reads SSE events from the open stream and `send()`
 *    POSTs additional messages to the same URL.
 *  - {@link encodeSSE} / {@link decodeSSE}: encode/decode helpers
 *    for callers that want to roll their own.
 *
 * @module
 */

import type { DialOptions, Transport } from "./transport.js";

/** Header name the server sets on its response to handshake init. */
export const SempSessionIdHeader = "Semp-Session-Id";

/** Path constants for the HTTP/2 binding per TRANSPORT.md §4.2.1. */
export const PathDiscovery = "/v1/discovery";
export const PathKeys = "/v1/keys";
export const PathHandshake = "/v1/handshake";
export const PathEnvelope = "/v1/envelope";
export const PathSession = "/v1/session/";

/**
 * Build the GET-lookup URL path for a discovery lookup per
 * TRANSPORT.md §4.2.1: `/v1/discovery/{address}`.
 */
export function discoveryPath(address: string): string {
  return `${PathDiscovery}/${address}`;
}

/**
 * Build the GET-lookup URL path for a key request per
 * TRANSPORT.md §4.2.1: `/v1/keys/{address}`.
 */
export function keysPath(address: string): string {
  return `${PathKeys}/${address}`;
}

/**
 * Build the GET-stream URL path for a session id per
 * TRANSPORT.md §4.2.4: `/v1/session/{id}`.
 */
export function sessionPath(sessionId: string): string {
  return `${PathSession}${sessionId}`;
}

/**
 * Minimal subset of the WHATWG fetch surface this module depends on.
 * Both Node 22+ and browsers ship `fetch` matching this shape. Tests
 * pass a fake to drive deterministic responses.
 */
export type H2FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: Uint8Array | string;
    signal?: AbortSignal;
  },
) => Promise<H2Response>;

/** Minimal Response surface this module consumes. */
export interface H2Response {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  /** Returns the full body as bytes. Used for one-shot request/response calls. */
  arrayBuffer(): Promise<ArrayBuffer>;
  /**
   * Async byte stream. Used for long-lived SSE session streams. May be
   * undefined for stub responses; in production it is the
   * `Response.body` `ReadableStream<Uint8Array>` (Node 22+ + browsers
   * support `for await` on this directly).
   */
  body?:
    | AsyncIterable<Uint8Array>
    | { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array }> } }
    | null;
}

// ---------------------------------------------------------------------------
// Request/response helper

/** Inputs to {@link h2Post}. */
export interface H2PostOptions extends DialOptions {
  /** Override the fetch implementation. Defaults to `globalThis.fetch`. */
  fetchImpl?: H2FetchLike;
  /**
   * `Semp-Session-Id` header to include on the request. Set on
   * subsequent handshake steps so the server can correlate them with
   * the session it minted in step 1.
   */
  sessionId?: string;
  /** Additional headers to merge in. */
  headers?: Record<string, string>;
}

/** Result of a successful {@link h2Post}. */
export interface H2PostResult {
  /** Decoded response body. */
  body: Uint8Array;
  /** HTTP status (always 2xx for `h2Post` resolutions). */
  status: number;
  /** `Semp-Session-Id` response header, if any. */
  sessionId: string | null;
}

/**
 * POST a SEMP message to one of the request/response endpoints
 * (`/v1/handshake`, `/v1/keys`, `/v1/envelope`, `/v1/discovery`).
 * Resolves with the response body and the `Semp-Session-Id` header.
 *
 * Translates HTTP status codes per §4.2.2:
 *  - 2xx: resolves successfully.
 *  - 400, 413, 429, 503: rejects with a structured error.
 *  - other non-2xx: rejects with the status as the message.
 */
export async function h2Post(
  url: string,
  message: Uint8Array,
  opts: H2PostOptions = {},
): Promise<H2PostResult> {
  if (url === "") {
    throw new Error("h2: empty url");
  }
  const fetchImpl = opts.fetchImpl ?? defaultFetch();
  const headers: Record<string, string> = {
    "Content-Type": "application/json; charset=utf-8",
    Accept: "application/json",
    ...(opts.headers ?? {}),
  };
  if (opts.sessionId !== undefined && opts.sessionId !== "") {
    headers[SempSessionIdHeader] = opts.sessionId;
  }

  const { signal, cleanup } = composeSignal(opts.signal, opts.timeoutMs);
  let resp: H2Response;
  try {
    resp = await fetchImpl(url, {
      method: "POST",
      headers,
      body: message,
      signal,
    });
  } finally {
    cleanup();
  }

  if (!resp.ok) {
    const reason = httpReason(resp.status);
    throw new Error(`h2: POST ${url} ${reason} (${resp.status})`);
  }

  const buf = await resp.arrayBuffer();
  return {
    body: new Uint8Array(buf),
    status: resp.status,
    sessionId: resp.headers.get(SempSessionIdHeader),
  };
}

function httpReason(status: number): string {
  switch (status) {
    case 400:
      return "malformed SEMP message";
    case 413:
      return "payload exceeds max_envelope_size";
    case 429:
      return "transport-level rate limit";
    case 503:
      return "server temporarily unavailable";
    default:
      return `HTTP ${status}`;
  }
}

// ---------------------------------------------------------------------------
// Long-lived session stream

/** Inputs to {@link dialH2Session}. */
export interface DialH2SessionOptions extends DialOptions {
  /** Override the fetch implementation. Defaults to `globalThis.fetch`. */
  fetchImpl?: H2FetchLike;
  /**
   * URL of the session endpoint, including the session id segment -
   * for example `https://semp.example.com/v1/session/01J...`. The
   * caller composes this from the configuration's
   * `endpoints.client.h2` base + the session id.
   */
  sessionUrl: string;
  /**
   * Optional initial body for the long-lived POST. Per §4.2.4 the
   * client opens a POST to `/v1/session/{id}`; the body is empty by
   * default but the caller MAY pass a stream of pre-buffered messages.
   */
  initialBody?: Uint8Array;
}

/**
 * Open a long-lived POST to the session URL and return a
 * {@link Transport} whose `receive()` reads SSE events from that
 * response and `send()` POSTs additional messages to the same URL.
 *
 * Per TRANSPORT.md §4.2.4: each `data:` line in the response carries
 * a complete SEMP JSON message; blank lines delimit events.
 */
export async function dialH2Session(
  opts: DialH2SessionOptions,
): Promise<Transport> {
  if (opts.sessionUrl === "") {
    throw new Error("h2: empty sessionUrl");
  }
  const fetchImpl = opts.fetchImpl ?? defaultFetch();
  const sendController = new AbortController();
  const composed = composeSignal(opts.signal, opts.timeoutMs);

  const headers: Record<string, string> = {
    "Content-Type": "application/json; charset=utf-8",
    Accept: "text/event-stream",
  };
  let resp: H2Response;
  try {
    resp = await fetchImpl(opts.sessionUrl, {
      method: "POST",
      headers,
      body: opts.initialBody,
      signal: composed.signal,
    });
  } catch (err) {
    composed.cleanup();
    throw err;
  }
  composed.cleanup();

  if (!resp.ok) {
    throw new Error(
      `h2: session POST ${opts.sessionUrl} ${httpReason(resp.status)} (${resp.status})`,
    );
  }
  if (resp.body === null || resp.body === undefined) {
    throw new Error("h2: session response has no body");
  }

  const eventReader = createEventReader(resp.body);
  let closed = false;
  const url = opts.sessionUrl;

  const transport: Transport = {
    async send(message: Uint8Array) {
      if (closed) {
        throw new Error("h2: session transport closed");
      }
      const r = await fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          Accept: "application/json",
        },
        body: message,
        signal: sendController.signal,
      });
      if (!r.ok) {
        throw new Error(
          `h2: session send ${httpReason(r.status)} (${r.status})`,
        );
      }
      // Discard the body; per spec, server-pushed messages arrive on
      // the SSE stream, not on the per-send response.
      await r.arrayBuffer();
    },
    async receive() {
      if (closed) {
        return null;
      }
      const event = await eventReader.read();
      if (event === null) {
        closed = true;
        return null;
      }
      return new TextEncoder().encode(event);
    },
    async close() {
      if (closed) {
        return;
      }
      closed = true;
      sendController.abort();
      eventReader.close();
    },
  };
  return transport;
}

// ---------------------------------------------------------------------------
// SSE encode

/**
 * Encode a single SEMP message as an SSE event. Each line in the
 * message body produces a `data:` line; the event is terminated with
 * a single blank line.
 *
 * The encoder normalizes CR / CRLF line terminators to LF before
 * emitting each `data:` line. SEMP payloads are JSON documents whose
 * control bytes are escaped (`\r`, `\n`), so the wire form never
 * actually carries a literal CR or LF - but be defensive.
 */
export function encodeSSE(message: string): string {
  const lines = splitSSELines(message);
  let out = "";
  for (const line of lines) {
    out += "data: " + line + "\n";
  }
  out += "\n";
  return out;
}

function splitSSELines(s: string): string[] {
  if (s === "") {
    return [""];
  }
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c !== 0x0d && c !== 0x0a) {
      continue;
    }
    out.push(s.slice(start, i));
    if (c === 0x0d && i + 1 < s.length && s.charCodeAt(i + 1) === 0x0a) {
      i++; // skip LF in CRLF
    }
    start = i + 1;
  }
  out.push(s.slice(start));
  return out;
}

// ---------------------------------------------------------------------------
// SSE decode

/**
 * Decode SSE events from a string buffer. Each call returns the next
 * complete event's `data` payload (or `null` if no complete event is
 * buffered yet). Stateful - the buffer accumulates partial input.
 */
export class SSEDecoder {
  private buffer = "";
  private dataLines: string[] = [];

  /** Append more bytes to the buffer. */
  push(chunk: string): void {
    this.buffer += chunk;
  }

  /**
   * Return the data payload of the next complete event, or `null` if
   * none is buffered. Repeatedly call until `null` to drain.
   */
  next(): string | null {
    while (true) {
      const lf = this.buffer.indexOf("\n");
      if (lf < 0) {
        return null;
      }
      let line = this.buffer.slice(0, lf);
      this.buffer = this.buffer.slice(lf + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }
      if (line === "") {
        if (this.dataLines.length > 0) {
          const event = this.dataLines.join("\n");
          this.dataLines = [];
          return event;
        }
        // Empty leading lines (keepalives) - skip.
        continue;
      }
      // Comment lines start with ":" - ignore.
      if (line.startsWith(":")) {
        continue;
      }
      // Field parse: "<field>:<value>" with optional space after colon.
      const colon = line.indexOf(":");
      let field: string;
      let value: string;
      if (colon < 0) {
        field = line;
        value = "";
      } else {
        field = line.slice(0, colon);
        value = line.slice(colon + 1);
        if (value.startsWith(" ")) {
          value = value.slice(1);
        }
      }
      if (field !== "data") {
        continue;
      }
      this.dataLines.push(value);
    }
  }

  /**
   * Flush any pending data lines as a final event. Called on EOF when
   * the underlying stream ends without a trailing blank line.
   */
  flush(): string | null {
    if (this.dataLines.length === 0) {
      return null;
    }
    const event = this.dataLines.join("\n");
    this.dataLines = [];
    return event;
  }
}

/** Decode all events present in a complete (already-buffered) SSE blob. */
export function decodeSSE(blob: string): string[] {
  const dec = new SSEDecoder();
  dec.push(blob);
  const out: string[] = [];
  while (true) {
    const ev = dec.next();
    if (ev === null) {
      break;
    }
    out.push(ev);
  }
  const trailing = dec.flush();
  if (trailing !== null) {
    out.push(trailing);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Async event reader

interface EventReader {
  read(): Promise<string | null>;
  close(): void;
}

function createEventReader(
  body:
    | AsyncIterable<Uint8Array>
    | { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array }> } },
): EventReader {
  const decoder = new SSEDecoder();
  const utf8 = new TextDecoder("utf-8");
  let done = false;
  let buffered: string | null = null;

  const iter = makeAsyncIterator(body);

  return {
    async read() {
      if (buffered !== null) {
        const out = buffered;
        buffered = null;
        return out;
      }
      while (true) {
        const ev = decoder.next();
        if (ev !== null) {
          return ev;
        }
        if (done) {
          return decoder.flush();
        }
        const result = await iter.next();
        if (result.done === true) {
          done = true;
          continue;
        }
        if (result.value === undefined) {
          continue;
        }
        decoder.push(utf8.decode(result.value, { stream: true }));
      }
    },
    close() {
      done = true;
      iter.return?.();
    },
  };
}

interface MinimalAsyncIterator {
  next(): Promise<{ done?: boolean; value?: Uint8Array }>;
  return?(): Promise<unknown>;
}

function makeAsyncIterator(
  body:
    | AsyncIterable<Uint8Array>
    | { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array }> } },
): MinimalAsyncIterator {
  if (typeof (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator] === "function") {
    const it = (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
    return it as MinimalAsyncIterator;
  }
  const reader = (body as { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array }> } }).getReader();
  return {
    async next() {
      return reader.read();
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers

interface ComposedSignal {
  signal: AbortSignal;
  cleanup: () => void;
}

function composeSignal(
  externalSignal: AbortSignal | undefined,
  timeoutMs: number | undefined,
): ComposedSignal {
  const controller = new AbortController();
  const timer = timeoutMs !== undefined && timeoutMs > 0
    ? setTimeout(() => controller.abort(), timeoutMs)
    : undefined;
  const externalListener = () => controller.abort();
  if (externalSignal !== undefined) {
    if (externalSignal.aborted) {
      controller.abort();
    } else {
      externalSignal.addEventListener("abort", externalListener, { once: true });
    }
  }
  return {
    signal: controller.signal,
    cleanup() {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      if (externalSignal !== undefined) {
        externalSignal.removeEventListener("abort", externalListener);
      }
    },
  };
}

function defaultFetch(): H2FetchLike {
  const f = (globalThis as unknown as { fetch?: H2FetchLike }).fetch;
  if (f === undefined) {
    throw new Error(
      "h2: globalThis.fetch is undefined. Pass a fetchImpl option, or run on Node 22+ / a browser.",
    );
  }
  return f;
}
