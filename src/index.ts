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

export * as crypto from "./crypto/index.js";
export * as handshake from "./handshake/index.js";
