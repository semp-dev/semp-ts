/**
 * Transport layer: SEMP runs over WebSocket (this submodule),
 * HTTP/2, and QUIC per `TRANSPORT.md` §4. Higher layers (handshake
 * driver, session machine) consume the abstract `Transport`
 * interface and are agnostic to the underlying socket.
 *
 * v0.x ships WebSocket. HTTP/2 and QUIC come in later releases.
 *
 * @module
 */

export { type DialOptions, type Transport } from "./transport.js";
export { type WSDialOptions, SempSubprotocol, dial as dialWS } from "./ws.js";
export { newPair as newMemoryPair } from "./memory.js";
