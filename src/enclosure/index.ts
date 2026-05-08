/**
 * Enclosure-layer compose helpers per ENVELOPE.md §6.
 *
 * Today: forwarding (3-signature chain). Future: large-attachment
 * enclosure pre-encryption helpers, sender-signature compose
 * convenience wrappers.
 *
 * @module
 */

export {
  type ComposeForwardedInput,
  type InnerEnclosurePlaintext,
  type OriginalEnvelopeRef,
  type OuterEnclosurePlaintext,
  type SignedForwardedEnclosure,
  composeForwarded,
} from "./forwarding.js";
