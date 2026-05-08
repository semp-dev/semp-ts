/**
 * Transport layer: SEMP runs over WebSocket, HTTP/2, and QUIC per
 * `TRANSPORT.md` §4. Higher layers (handshake driver, session
 * machine) consume the abstract `Transport` interface and are
 * agnostic to the underlying socket.
 *
 * v0.x ships WebSocket and HTTP/2. QUIC comes in a later release.
 *
 * @module
 */

export { type DialOptions, type Transport } from "./transport.js";
export { type WSDialOptions, SempSubprotocol, dial as dialWS } from "./ws.js";
export { newPair as newMemoryPair } from "./memory.js";
export {
  type DialH2SessionOptions,
  type H2FetchLike,
  type H2PostOptions,
  type H2PostResult,
  type H2Response,
  SSEDecoder,
  SempSessionIdHeader,
  decodeSSE,
  dialH2Session,
  encodeSSE,
  h2Post,
} from "./h2.js";
