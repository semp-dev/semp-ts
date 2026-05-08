/**
 * Delivery layer per DELIVERY.md.
 *
 * Today: signed delivery receipts (§1.1.1) — compose, verify,
 * envelope-binding cross-check, and a transient receipt store for
 * the sending server. Future slices: ack envelope shape
 * (`delivered` / `rejected` / `silent`), recipient status
 * (§1.6), retry queue (§2), block list (§5).
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
