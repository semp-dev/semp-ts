/**
 * SEMP: Sealed Envelope Messaging Protocol — TypeScript implementation.
 *
 * @see {@link https://github.com/semp-dev/semp-spec}
 *
 * This entry point re-exports the most commonly used names from each
 * layer. Callers who want a smaller import surface can target a
 * specific sub-module: `import { newHKDFSHA512 } from "semp/crypto"`.
 *
 * @module
 */

export * as canonical from "./canonical/index.js";
export * as clockskew from "./clockskew/index.js";
export * as crypto from "./crypto/index.js";
export * as discovery from "./discovery/index.js";
export * as enclosure from "./enclosure/index.js";
export * as envelope from "./envelope/index.js";
export * as extensions from "./extensions/index.js";
export * as handshake from "./handshake/index.js";
export * as keys from "./keys/index.js";
export * as migration from "./migration/index.js";
export * as seal from "./seal/index.js";
export * as session from "./session/index.js";
export * as transport from "./transport/index.js";

export {
  type ReasonCode,
  KnownReasonCodes,
  isKnownReasonCode,
  isRecoverable,
} from "./reasoncodes.js";
