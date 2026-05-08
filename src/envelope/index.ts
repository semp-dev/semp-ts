/**
 * Envelope layer: §4.3 canonical serialization and §2.4.1 / §4.4.2
 * bucket math. Wire compose/open paths land in later waves.
 *
 * @module
 */

export { canonicalEnvelopeBytes } from "./canonical.js";
export {
  selectSizeBucket,
  selectRecipientCountBucket,
  MinEnvelopeSizeBucket,
  DefaultMaxEnvelopeSize,
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
