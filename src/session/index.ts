/**
 * Session lifecycle layer per `SESSION.md`. Holds the post-handshake
 * keys, TTL, transport, and permission set; lifts the runClient
 * result into a usable session object.
 *
 * Future slices: rekey, resume, sequence-number tracking.
 *
 * @module
 */

export { type Role, type SessionConfig, Session } from "./session.js";
