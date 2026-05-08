/**
 * Canonical JSON serialization per ENVELOPE.md §4.3. Used as the
 * byte stream for every SEMP signature and MAC computation.
 *
 * @module
 */

export { marshal, marshalWithElision } from "./marshal.js";
