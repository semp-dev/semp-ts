/**
 * Session lifecycle layer per `SESSION.md`. Holds the post-handshake
 * keys, TTL, transport, and permission set; lifts the runClient
 * result into a usable session object.
 *
 * Future slices: rekey, resume, sequence-number tracking.
 *
 * @module
 */

export {
  type RekeyApply,
  type Role,
  type SessionConfig,
  Session,
} from "./session.js";
export {
  type SealedRekey,
  openRekeyMessage,
  sealRekeyMessage,
} from "./rekey_seal.js";
export {
  type RekeyAccepted,
  type RekeyClientOptions,
  type RekeyInit,
  type RekeyRejected,
  type RekeyServerOptions,
  RekeyRejectedError,
  rekeyClient,
  rekeyServer,
} from "./rekey.js";
export {
  type ResumeAccepted,
  type ResumeClientConfig,
  type ResumeRequest,
  type ResumeServerConfig,
  type TicketLookupResult,
  resumeClient,
  resumeServer,
} from "./resume.js";
