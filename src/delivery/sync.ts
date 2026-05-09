/**
 * SEMP_BLOCK block-list sync wire shape per DELIVERY.md §6.1.
 *
 * Used to propagate block-list changes from a client to its home
 * server and onward to the user's other devices. The message MUST
 * be signed by the originating device's identity key. The home
 * server MUST verify the signature before storing or propagating
 * (DELIVERY.md §6.2 / §8.2).
 *
 * @module
 */

import { type BlockEntry } from "./blocklist.js";
import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

/** Wire-level type discriminator. */
export const SyncMessageType = "SEMP_BLOCK";

/** Schema version. */
export const SyncMessageVersion = "1.0.0";

/** The only defined step. */
export const SyncStep = "update";

/** Domain-separation prefix; SEMP_BLOCK uses no extra prefix beyond the SEMP-REVOCATION-style canonical-blanked pattern. */
export const SyncMessagePrefix = "SEMP-BLOCK:";

/** Sync operation verb. */
export type SyncOp = "add" | "remove" | "modify";

/** One entry in {@link SyncMessage.operations}. */
export interface SyncOperation {
  op: SyncOp;
  /** For `remove` and `modify`. */
  entry_id?: string;
  /** For `add` and `modify`. */
  entry?: BlockEntry;
}

/** SEMP_BLOCK reusable signature block. */
export interface SyncSignatureBlock {
  algorithm: string;
  key_id: string;
  /** Base64. */
  value: string;
}

/**
 * SEMP_BLOCK sync message per DELIVERY.md §6.1.
 *
 * Signed by the originating device's identity key under the
 * `SEMP-BLOCK:` prefix; the canonical bytes are computed with
 * `signature.value` blanked.
 */
export interface SyncMessage {
  type: typeof SyncMessageType;
  step: typeof SyncStep;
  version: string;
  user_id: string;
  device_id: string;
  list_version: number;
  /** ISO 8601 UTC. */
  timestamp: string;
  operations: SyncOperation[];
  signature: SyncSignatureBlock;
}

/**
 * Sign `m.signature` with the originating device's identity private
 * key per §6.2. Mutates `m` in place. Returns the base64 signature.
 */
export function signSyncMessage(
  m: SyncMessage,
  devicePriv: Uint8Array,
  deviceKeyId: string,
): string {
  if (deviceKeyId === "") {
    throw new Error("delivery: empty device key_id");
  }
  validateSyncMessage(m, { skipSignatureCheck: true });
  m.signature.algorithm = "ed25519";
  m.signature.key_id = deviceKeyId;
  m.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: m as unknown as Record<string, unknown>,
    seed: devicePriv,
    signaturePath: "signature.value",
    prefix: SyncMessagePrefix,
  });
  m.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify `m.signature` against the originating device's identity public key. */
export function verifySyncMessage(
  m: SyncMessage,
  devicePub: Uint8Array,
): boolean {
  validateSyncMessage(m);
  if (m.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: m as unknown as Record<string, unknown>,
    publicKey: devicePub,
    signaturePath: "signature.value",
    prefix: SyncMessagePrefix,
  });
  return ok;
}

/** Structural validation per §6.1. Throws on first violation. */
export function validateSyncMessage(
  m: SyncMessage,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (m.type !== SyncMessageType) {
    throw new Error(
      `delivery: sync message type ${JSON.stringify(m.type)}, want ${SyncMessageType}`,
    );
  }
  if (m.step !== SyncStep) {
    throw new Error(
      `delivery: sync message step ${JSON.stringify(m.step)}, want ${SyncStep}`,
    );
  }
  for (const f of ["version", "user_id", "device_id", "timestamp"] as const) {
    if (typeof m[f] !== "string" || m[f] === "") {
      throw new Error(`delivery: sync message missing ${f}`);
    }
  }
  if (Number.isNaN(Date.parse(m.timestamp))) {
    throw new Error("delivery: sync message timestamp is not ISO 8601");
  }
  if (
    !Number.isInteger(m.list_version) ||
    m.list_version < 0
  ) {
    throw new Error(
      `delivery: sync message list_version ${m.list_version} MUST be an unsigned integer`,
    );
  }
  if (!Array.isArray(m.operations) || m.operations.length === 0) {
    throw new Error("delivery: sync message operations MUST be non-empty");
  }
  for (let i = 0; i < m.operations.length; i++) {
    const op = m.operations[i]!;
    if (op.op !== "add" && op.op !== "remove" && op.op !== "modify") {
      throw new Error(
        `delivery: sync operations[${i}] op ${JSON.stringify(op.op)} is invalid`,
      );
    }
    if (op.op === "remove" && (op.entry_id === undefined || op.entry_id === "")) {
      throw new Error(
        `delivery: sync operations[${i}] op=remove MUST set entry_id`,
      );
    }
    if (op.op === "add" && (op.entry === undefined || op.entry === null)) {
      throw new Error(
        `delivery: sync operations[${i}] op=add MUST carry entry`,
      );
    }
  }
  if (typeof m.signature?.value !== "string") {
    throw new Error("delivery: sync message signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && m.signature.value === "") {
    throw new Error("delivery: sync message is unsigned");
  }
}
