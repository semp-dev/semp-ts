/**
 * WebSocket transport for SEMP per `TRANSPORT.md` §4.1.
 *
 * Wire shape:
 *   - URL scheme: `wss://` (TLS REQUIRED; plain `ws://` is prohibited
 *     by the spec but accepted in tests against local servers).
 *   - Subprotocol: `semp.v1` (advertised in the Upgrade handshake
 *     and confirmed by the server; mismatch closes the connection).
 *   - One SEMP message per WebSocket TEXT frame, UTF-8 JSON.
 *     Binary frames MUST NOT carry SEMP messages.
 *
 * Targets the WHATWG WebSocket API — works natively in Node 22+ and
 * every browser. No `ws` npm package or other dependency.
 *
 * @module
 */

import type { DialOptions, Transport } from "./transport.js";

/** Subprotocol advertised in the Upgrade handshake per §4.1.1. */
export const SempSubprotocol = "semp.v1";

/** Default timeout for {@link dial} when `signal` is not supplied. */
const DefaultDialTimeoutMs = 30_000;

/** Options specific to the WebSocket dialer. */
export interface WSDialOptions extends DialOptions {
  /**
   * Allow `ws://` (insecure) URLs. Defaults to false. Production
   * deployments MUST keep this off; tests against localhost set
   * it for development convenience.
   */
  allowInsecure?: boolean;
}

class WSTransport implements Transport {
  private ws: WebSocket;
  private buffer: Uint8Array[] = [];
  private waiters: Array<{
    resolve: (msg: Uint8Array | null) => void;
    reject: (err: Error) => void;
  }> = [];
  private closed = false;
  private closeError: Error | null = null;

  constructor(ws: WebSocket) {
    this.ws = ws;
    ws.binaryType = "arraybuffer";

    ws.addEventListener("message", (ev: Event) => {
      // Spec §4.1.2: SEMP messages MUST be text frames. A binary
      // frame is a framing violation; close the connection.
      const data = (ev as Event & { data: unknown }).data;
      if (typeof data !== "string") {
        const err = new Error(
          "transport/ws: binary frame received; SEMP messages MUST be text",
        );
        this.failAll(err);
        try {
          ws.close(1003, "binary frame disallowed");
        } catch {
          // already closing/closed
        }
        return;
      }
      const bytes = new TextEncoder().encode(data);
      const next = this.waiters.shift();
      if (next !== undefined) {
        next.resolve(bytes);
      } else {
        this.buffer.push(bytes);
      }
    });

    ws.addEventListener("close", (_ev: Event) => {
      this.closed = true;
      // Drain any waiters with null (clean close).
      const drained = this.waiters.splice(0);
      for (const w of drained) {
        w.resolve(null);
      }
    });

    ws.addEventListener("error", () => {
      // The WHATWG event has no `error` property. Surface a
      // generic error so callers see SOMETHING; the close event
      // (if it fires) will carry a code/reason.
      this.failAll(new Error("transport/ws: connection error"));
    });
  }

  send(message: Uint8Array): Promise<void> {
    if (this.closed) {
      return Promise.reject(this.closeError ?? new Error("transport/ws: closed"));
    }
    // Native WebSocket.send accepts strings (text frame) or
    // ArrayBuffer (binary frame). Per §4.1.2 we always send text.
    this.ws.send(new TextDecoder().decode(message));
    return Promise.resolve();
  }

  receive(): Promise<Uint8Array | null> {
    const buffered = this.buffer.shift();
    if (buffered !== undefined) {
      return Promise.resolve(buffered);
    }
    if (this.closed) {
      return Promise.resolve(this.closeError !== null ? Promise.reject(this.closeError) : null);
    }
    return new Promise<Uint8Array | null>((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  close(code?: number, reason?: string): Promise<void> {
    if (this.closed) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      const onClose = (): void => {
        this.ws.removeEventListener("close", onClose);
        resolve();
      };
      this.ws.addEventListener("close", onClose);
      this.ws.close(code, reason);
    });
  }

  private failAll(err: Error): void {
    this.closeError = err;
    this.closed = true;
    const drained = this.waiters.splice(0);
    for (const w of drained) {
      w.reject(err);
    }
  }
}

/**
 * Open a WebSocket transport to `url` and complete the SEMP
 * subprotocol negotiation. Resolves with a connected `Transport`
 * once the server confirms `semp.v1`; rejects on connect failure,
 * timeout, abort, or subprotocol mismatch.
 *
 * In the browser, the user-agent enforces the subprotocol check
 * for us (a non-matching server response surfaces as `wasClean=false`
 * close). On Node we additionally validate `ws.protocol` after open.
 */
export async function dial(
  url: string,
  options: WSDialOptions = {},
): Promise<Transport> {
  if (!url.startsWith("wss://")) {
    if (!url.startsWith("ws://") || options.allowInsecure !== true) {
      throw new Error(
        `transport/ws: ${url}: scheme must be wss:// (set allowInsecure for ws://)`,
      );
    }
  }

  const ws = new WebSocket(url, [SempSubprotocol]);
  ws.binaryType = "arraybuffer";

  return new Promise<Transport>((resolve, reject) => {
    const timeoutMs = options.timeoutMs ?? DefaultDialTimeoutMs;
    let settled = false;
    const cleanup = (): void => {
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("close", onClose);
      ws.removeEventListener("error", onError);
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      if (options.signal !== undefined) {
        options.signal.removeEventListener("abort", onAbort);
      }
    };
    const fail = (err: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      try {
        ws.close();
      } catch {
        // already closing/closed
      }
      reject(err);
    };

    const onOpen = (): void => {
      if (settled) {
        return;
      }
      // The server MUST confirm the subprotocol; if it didn't, the
      // user-agent typically fails the connection before `open`,
      // but Node's WHATWG implementation populates `ws.protocol`
      // and we cross-check defensively.
      if (ws.protocol !== "" && ws.protocol !== SempSubprotocol) {
        fail(new Error(
          `transport/ws: server confirmed unexpected subprotocol "${ws.protocol}"`,
        ));
        return;
      }
      settled = true;
      cleanup();
      resolve(new WSTransport(ws));
    };

    const onClose = (ev: Event): void => {
      // The WHATWG CloseEvent carries `code` and `reason`; the
      // generic `Event` type does not, so we cast at the boundary.
      const ce = ev as Event & { code?: number; reason?: string };
      fail(
        new Error(
          `transport/ws: closed before open (code=${ce.code ?? "?"}, reason=${ce.reason ?? ""})`,
        ),
      );
    };

    const onError = (): void => {
      fail(new Error("transport/ws: connect error"));
    };

    const onAbort = (): void => {
      fail(new Error(`transport/ws: aborted: ${options.signal?.reason ?? "unknown"}`));
    };

    let timer: ReturnType<typeof setTimeout> | undefined;
    if (options.signal === undefined) {
      timer = setTimeout(() => {
        fail(new Error(`transport/ws: timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    } else {
      if (options.signal.aborted) {
        fail(new Error(`transport/ws: aborted: ${options.signal.reason ?? "unknown"}`));
        return;
      }
      options.signal.addEventListener("abort", onAbort);
    }

    ws.addEventListener("open", onOpen);
    ws.addEventListener("close", onClose);
    ws.addEventListener("error", onError);
  });
}
