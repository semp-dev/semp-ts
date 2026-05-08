/**
 * Delivery layer per DELIVERY.md.
 *
 * Today: signed delivery receipts (§1.1.1) plus the per-attempt
 * acknowledgment envelope (§1.1.1.5 / §1.6) — the wire shape a
 * recipient server returns inline, including recipient-status
 * visibility resolution (§1.6.4). Future slices: retry queue (§2),
 * block list (§5), full delivery pipeline (§3).
 *
 * @module
 */

export {
  type DeliveryReceipt,
  type EnvelopeHash,
  type ReceiptSignature,
  type SignDeliveryReceiptInput,
  type SignDeliveryReceiptResult,
  type VerifyDeliveryReceiptInput,
  DeliveryReceiptPrefix,
  DeliveryReceiptType,
  DeliveryReceiptVersion,
  EnvelopeHashAlgorithmSHA256,
  ReceiptClockSkewToleranceSeconds,
  ReceiptSignatureAlgorithmEd25519,
  computeEnvelopeHash,
  signDeliveryReceipt,
  validateReceipt,
  verifyDeliveryReceipt,
  verifyEnvelopeBinding,
} from "./receipt.js";

export {
  type ReceiptStore,
  DefaultReceiptRetentionMs,
  InMemoryReceiptStore,
} from "./receipt_store.js";

export {
  type Acknowledgment,
  type DeliveryAck,
  type RecipientState,
  type RecipientStatus,
  type SenderIdentity,
  type Visibility,
  type VisibilityEntry,
  type VisibilityMode,
  MaxStatusMessageBytes,
  buildDeliveredAck,
  buildRejectedAck,
  matchVisibility,
  validateRecipientStatus,
} from "./ack.js";
