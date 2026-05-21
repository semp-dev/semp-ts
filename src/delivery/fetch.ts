/**
 * SEMP_FETCH wire shapes - the demo-only client -> home-server inbox
 * pull protocol per CLIENT.md §3.
 *
 * HANDSHAKE.md §4.6 explicitly leaves the client wakeup mechanism
 * outside the scope of the spec: "How a server notifies a client
 * that incoming messages are waiting is outside the scope of this
 * specification. Implementations MAY use persistent WebSocket
 * connections, long polling, or platform notification services such
 * as APNs or FCM."
 *
 * `SEMP_FETCH` is the simplest possible such mechanism: the client,
 * after completing the handshake, sends a single `SEMP_FETCH`
 * request and the server responds with the contents of the client's
 * inbox. It is fit for demo and test purposes only; a real
 * deployment would use a long-lived notification stream or platform
 * push.
 *
 * @module
 */

/** Wire-level type discriminator. */
export const FetchType = "SEMP_FETCH";

/** Schema version. */
export const FetchVersion = "1.0.0";

/** Discriminator for which fetch message variant this is. */
export type FetchStep = "request" | "response";

/** Sent by the client to pull every waiting envelope from the inbox. */
export interface FetchRequest {
  type: typeof FetchType;
  step: "request";
  version: string;
}

/** Construct a {@link FetchRequest} with the protocol version pre-populated. */
export function newFetchRequest(): FetchRequest {
  return {
    type: FetchType,
    step: "request",
    version: FetchVersion,
  };
}

/**
 * Server's response carrying the envelopes being delivered. Each
 * element of `envelopes` is the base64-encoded canonical JSON of a
 * single SEMP envelope (the same bytes the sender produced; the
 * recipient runs `decodeEnvelope` and `openBriefAny` /
 * `openEnclosureAny` on each).
 *
 * `drained` reports whether the server returned every envelope it
 * had queued for the recipient. The demo server always sets this to
 * `true` because the inbox is unbounded; production implementations
 * might paginate and set `drained === false`.
 */
export interface FetchResponse {
  type: typeof FetchType;
  step: "response";
  version: string;
  /** Base64-encoded envelope payloads. */
  envelopes: string[];
  drained: boolean;
  /** ISO 8601 UTC. */
  timestamp: string;
}

/** Construct a fully-populated {@link FetchResponse}. */
export function newFetchResponse(
  envelopesB64: string[],
  nowFn: () => Date = () => new Date(),
): FetchResponse {
  return {
    type: FetchType,
    step: "response",
    version: FetchVersion,
    envelopes: envelopesB64,
    drained: true,
    timestamp: isoSecond(nowFn()),
  };
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
