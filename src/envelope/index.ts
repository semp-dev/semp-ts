/**
 * Envelope layer per ENVELOPE.md §2 + §4 + §6 + §7.
 *
 * Compose / open / verify primitives + bucket math + padding +
 * send-time obfuscation + wire-format encode/decode + typed
 * rejection error.
 *
 * @module
 */

export { canonicalEnvelopeBytes } from "./canonical.js";

export {
  DefaultMaxEnvelopeSize,
  MinEnvelopeSizeBucket,
  selectRecipientCountBucket,
  selectSizeBucket,
} from "./buckets.js";

export {
  type ComposeInput,
  type Envelope,
  type OpenedEnvelope,
  type OpenInput,
  type PostmarkFields,
  type RecipientKey,
  canonicalEnvelopeFor,
  compose,
  openForRecipient,
} from "./compose.js";

export {
  EnvelopeFileExtension,
  EnvelopeMIMEType,
  decodeEnvelope,
  decodeEnvelopeFile,
  encodeEnvelope,
  encodeEnvelopeFile,
} from "./encode.js";

export { verifySealSignature, verifySessionMAC } from "./verify.js";

export {
  type OpenedBrief,
  type OpenedEnclosure,
  type RecipientCandidate,
  openBriefAny,
  openEnclosureAny,
} from "./open_any.js";

export {
  type OpenAndVerifyInput,
  type OpenAndVerifyResult,
  type SenderKeyResolver,
  type SenderKeyResolverFunc,
  openAndVerify,
} from "./open_verified.js";

export {
  type PadConfig,
  Ed25519SignatureB64Len,
  HMACSHA256B64Len,
  buildPaddingValue,
  fillPadding,
} from "./padding.js";

export {
  type SendTimeDelayConfig,
  DefaultSendTimeDelayCeilingMs,
  sendTimeDelay,
} from "./sendtime.js";

export { EnvelopeRejection, isEnvelopeRejection } from "./rejection.js";
