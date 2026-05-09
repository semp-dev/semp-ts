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
  ImplementedSuites,
  SuitePreferenceOrder,
  defaultClientCapabilities,
  defaultServerCapabilities,
  negotiateCapabilities,
} from "./capabilities.js";
export {
  ChallengeInvalidError,
  buildClientRejection,
  isChallengeInvalid,
  isResumptionFailed,
} from "./abort.js";
export {
  type ClientConfig,
  type ClientSession,
  type HandshakeSuite,
  HandshakeRejectedError,
  runClient,
} from "./driver.js";
export {
  type HandshakeClientConfig,
  type HandshakeClientSession,
  HandshakeClient,
} from "./client_state.js";
export {
  type HandshakeServerConfig,
  type HandshakeServerSession,
  HandshakeServer,
  HandshakeServerRejectionError,
} from "./server_state.js";
export {
  runClientResume,
  runClientResumeOrFull,
} from "./resume_driver.js";
export {
  type DomainProof,
  type DomainProofMethod,
  type DomainVerificationResult,
  type DomainVerifier,
  type FederationAcceptance,
  type FederationAccepted,
  type FederationConfirm,
  type FederationEphemeralKey,
  type FederationInitiatorConfig,
  type FederationInitiatorSession,
  type FederationPolicy,
  type FederationProof,
  type FederationResponderConfig,
  type FederationResponderSession,
  type FederationResponse,
  type FederationResume,
  type PolicyAcceptor,
  type ServerInit,
  FederationInitiator,
  FederationMessageType,
  FederationResponder,
  TrustingDomainVerifier,
  acceptAllPolicies,
  resolveCollision,
} from "./federation.js";
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
