/**
 * Seal layer per ENVELOPE.md §4.4. Per-recipient key wrap +
 * eventual signature/MAC over the canonical envelope bytes.
 *
 * @module
 */

export { type Suite, WrapInfo, unwrap } from "./wrap.js";
