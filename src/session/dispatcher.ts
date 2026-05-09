/**
 * Session message dispatcher.
 *
 * Reads frames off a Session's transport in a loop, parses the
 * outermost `type` field, and routes each frame to the matching
 * caller-supplied handler. Designed for the long-running phase
 * after a successful handshake — when the wire carries a mix of
 * envelopes, sealed rekey messages, key-fetch requests, etc.
 *
 * The dispatcher does NOT verify envelope signatures or open
 * sealed payloads itself; those are concerns of the per-type
 * handlers. Its job is solely message-type fan-out and lifecycle.
 *
 * @module
 */

import type { Session } from "./session.js";

/** Handlers registered on a {@link runDispatcher} call. */
export interface DispatchHandlers {
  /**
   * Sealed rekey message. The dispatcher reads the bytes off the
   * transport and invokes this with the JSON object (already
   * parsed). Production callers route through {@link "./rekey".rekeyServer}
   * by feeding the bytes back through their own transport-level
   * input — see the dispatcher example in the README.
   */
  onRekey?: (frame: Uint8Array, parsed: unknown) => Promise<void> | void;

  /** A wire envelope (`type: SEMP_ENVELOPE`). */
  onEnvelope?: (frame: Uint8Array, parsed: unknown) => Promise<void> | void;

  /** A SEMP_KEYS request or response. */
  onKeys?: (frame: Uint8Array, parsed: unknown) => Promise<void> | void;

  /** A SEMP_FETCH inbox-pull frame. */
  onFetch?: (frame: Uint8Array, parsed: unknown) => Promise<void> | void;

  /** A SEMP_DISCOVERY response delivered over an in-session channel. */
  onDiscovery?: (frame: Uint8Array, parsed: unknown) => Promise<void> | void;

  /** A SEMP_DELIVERY_ACK or SEMP_DELIVERY_RECEIPT. */
  onDelivery?: (frame: Uint8Array, parsed: unknown) => Promise<void> | void;

  /**
   * Any frame whose `type` field doesn't match a registered
   * handler. The default behavior (when this handler is not
   * supplied) is to silently drop unknown types per the protocol
   * forward-compatibility rule. Logging-level callers register
   * this hook to surface unknowns at WARN.
   */
  onUnknown?: (type: string, frame: Uint8Array) => Promise<void> | void;

  /**
   * Invoked on a non-fatal error inside a handler. The dispatcher
   * loop continues — the caller MUST decide whether to close the
   * session. If this is not supplied, handler errors are swallowed.
   */
  onHandlerError?: (err: Error, type: string) => void;

  /**
   * Invoked on a fatal transport / parse error. The dispatcher
   * exits its loop after calling this. If not supplied, the loop
   * exits silently on fatal errors and {@link runDispatcher}
   * resolves.
   */
  onFatal?: (err: Error) => void;
}

/**
 * Run the dispatcher loop. Resolves when the session closes
 * cleanly (peer EOF) OR after a fatal error has been surfaced
 * to {@link DispatchHandlers.onFatal}. Does NOT close the
 * session; the caller decides whether to call `session.close()`
 * after this resolves.
 */
export async function runDispatcher(
  session: Session,
  handlers: DispatchHandlers,
): Promise<void> {
  while (true) {
    let frame: Uint8Array | null;
    try {
      frame = await session.receive();
    } catch (err) {
      handlers.onFatal?.(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    if (frame === null) {
      // Clean EOF.
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(frame));
    } catch (err) {
      handlers.onFatal?.(
        new Error(
          `dispatcher: malformed frame: ${err instanceof Error ? err.message : String(err)}`,
        ),
      );
      return;
    }
    const type = typeof (parsed as { type?: unknown }).type === "string"
      ? (parsed as { type: string }).type
      : "";

    try {
      await dispatchOne(type, frame, parsed, handlers);
    } catch (err) {
      handlers.onHandlerError?.(
        err instanceof Error ? err : new Error(String(err)),
        type,
      );
      // Continue the loop; handler errors are non-fatal by default.
    }
  }
}

async function dispatchOne(
  type: string,
  frame: Uint8Array,
  parsed: unknown,
  handlers: DispatchHandlers,
): Promise<void> {
  switch (type) {
    case "SEMP_REKEY":
      if (handlers.onRekey !== undefined) {
        await handlers.onRekey(frame, parsed);
        return;
      }
      break;
    case "SEMP_ENVELOPE":
      if (handlers.onEnvelope !== undefined) {
        await handlers.onEnvelope(frame, parsed);
        return;
      }
      break;
    case "SEMP_KEYS":
      if (handlers.onKeys !== undefined) {
        await handlers.onKeys(frame, parsed);
        return;
      }
      break;
    case "SEMP_FETCH":
      if (handlers.onFetch !== undefined) {
        await handlers.onFetch(frame, parsed);
        return;
      }
      break;
    case "SEMP_DISCOVERY":
      if (handlers.onDiscovery !== undefined) {
        await handlers.onDiscovery(frame, parsed);
        return;
      }
      break;
    case "SEMP_DELIVERY_ACK":
    case "SEMP_DELIVERY_RECEIPT":
      if (handlers.onDelivery !== undefined) {
        await handlers.onDelivery(frame, parsed);
        return;
      }
      break;
  }
  if (handlers.onUnknown !== undefined) {
    await handlers.onUnknown(type, frame);
  }
  // else silently drop, per protocol forward-compatibility.
}
