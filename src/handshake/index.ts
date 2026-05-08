/**
 * Handshake-layer primitives: PoW verification, confirmation hash,
 * and (in later waves) the canonical message bytes for init,
 * response, confirm, accepted, rejected.
 *
 * @module
 */

export { confirmationHash } from "./confirm.js";
export {
  verifyChallengeSolution,
  firstContactDigest,
  leadingZeroBits,
  MaxPoWDifficulty,
} from "./pow.js";
export {
  FirstContactBindingHashSize,
  FirstContactBindingTag,
  FirstContactFieldSep,
  FirstContactPrefixRandBytes,
  computeFirstContactPrefix,
  decodeFirstContactPrefix,
  verifyFirstContactBinding,
} from "./first_contact.js";
export {
  type ClientConfig,
  type ClientSession,
  HandshakeRejectedError,
  runClient,
} from "./driver.js";
export {
  type IdentityProofVerdict,
  type ServerConfig,
  runServer,
} from "./server.js";
export {
  type ComposeIdentityProofInput,
  type IdentityProofBlock,
  type OpenIdentityProofInput,
  IdentityPrefix,
  composeIdentityProof,
  openIdentityProof,
} from "./identity.js";
export {
  type AcceptedMessage,
  type BuildAcceptedInput,
  type BuildConfirmInput,
  type BuildInitInput,
  type BuildRejectedInput,
  type BuildResponseInput,
  type Capabilities,
  type ConfirmMessage,
  type InitMessage,
  type KeyRef,
  type Negotiated,
  type RejectedMessage,
  type ResponseMessage,
  type ResumptionTicket,
  type ServerIdentityProof,
  HandshakePrefix,
  HandshakeVersion,
  buildAccepted,
  buildConfirm,
  buildInit,
  buildRejected,
  buildResponse,
} from "./messages.js";
