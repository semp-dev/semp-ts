/**
 * SEMP_STATUS recipient-status configuration message per
 * draft-gokce-semp-delivery §1.6.5.
 *
 * The client composes a signed StatusMessage carrying the user's
 * state, optional message and until, plus the visibility rule
 * that determines which senders may receive the status in
 * acknowledgments. The client transmits the record to the home
 * server as a signed message under the originating device's key;
 * the home server verifies, checks device_id against the
 * registered device set, and applies the latest update by
 * updated_at.
 *
 * This is distinct from the runtime recipient-status surface in
 * `./status.ts` (the value attached to delivery acknowledgments).
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

/** Wire-level type discriminator. */
export const StatusMessageType = "SEMP_STATUS";

/** Wire-level version. */
export const StatusMessageVersion = "1.0.0";

/** Domain-separation prefix for SEMP_STATUS signatures. */
export const StatusMessagePrefix = "SEMP-STATUS:";

/** Recipient state value pinned by §1.6.3. */
export type StatusState = "available" | "away" | "do_not_disturb";

/** Visibility mode for the SEMP_STATUS record per §1.6.5. */
export type StatusVisibilityMode = "nobody" | "everyone" | "users";

/** Single entry in StatusVisibility.allow. */
export type StatusVisibilityEntry =
  | { type: "domain"; domain: string }
  | { type: "user"; address: string };

/** Visibility configuration per §1.6.5. */
export interface StatusVisibility {
  mode: StatusVisibilityMode;
  allow?: StatusVisibilityEntry[];
}

/** Signature block on a SEMP_STATUS message. */
export interface StatusMessageSignature {
  algorithm: string;
  key_id: string;
  value: string;
}

/** SEMP_STATUS configuration record per §1.6.5. */
export interface StatusMessage {
  type: typeof StatusMessageType;
  version: string;
  user_id: string;
  state: StatusState | string;
  message?: string;
  /** ISO 8601 UTC. */
  until?: string;
  visibility: StatusVisibility;
  /** ISO 8601 UTC. */
  updated_at: string;
  device_id: string;
  signature: StatusMessageSignature;
}

/**
 * Sign `m.signature` with the originating device's identity
 * private key under the SEMP-STATUS: prefix. Mutates m in place
 * and returns the base64 signature value.
 */
export function signStatusMessage(
  m: StatusMessage,
  devicePriv: Uint8Array,
  deviceKeyId: string,
): string {
  if (deviceKeyId === "") {
    throw new Error("delivery: empty device key_id");
  }
  if ((m.type as string) === "") {
    m.type = StatusMessageType;
  }
  if (m.version === "") {
    m.version = StatusMessageVersion;
  }
  validateStatusMessage(m, { skipSignatureCheck: true });
  m.signature.algorithm = "ed25519";
  m.signature.key_id = deviceKeyId;
  m.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: m as unknown as Record<string, unknown>,
    seed: devicePriv,
    signaturePath: "signature.value",
    prefix: StatusMessagePrefix,
  });
  m.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify `m.signature` against the originating device's public key. */
export function verifyStatusMessage(
  m: StatusMessage,
  devicePub: Uint8Array,
): boolean {
  validateStatusMessage(m);
  if (m.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: m as unknown as Record<string, unknown>,
    publicKey: devicePub,
    signaturePath: "signature.value",
    prefix: StatusMessagePrefix,
  });
  return ok;
}

/** Structural validation per §1.6.5. */
export function validateStatusMessage(
  m: StatusMessage,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (m.type !== StatusMessageType) {
    throw new Error(
      `delivery: status message type ${JSON.stringify(m.type)}, want ${StatusMessageType}`,
    );
  }
  if (m.version === "") {
    throw new Error("delivery: status message missing version");
  }
  if (m.user_id === "") {
    throw new Error("delivery: status message missing user_id");
  }
  if ((m.state as string) === "") {
    throw new Error("delivery: status message missing state");
  }
  if (m.device_id === "") {
    throw new Error("delivery: status message missing device_id");
  }
  if (m.updated_at === "") {
    throw new Error("delivery: status message missing updated_at");
  }
  if ((m.visibility.mode as string) === "") {
    throw new Error("delivery: status message visibility.mode is empty");
  }
  if (m.visibility.allow !== undefined) {
    for (let i = 0; i < m.visibility.allow.length; i++) {
      const e = m.visibility.allow[i];
      if (e === undefined) {
        continue;
      }
      if (e.type === "domain" && e.domain === "") {
        throw new Error(
          `delivery: status visibility.allow[${i}] type=domain missing domain`,
        );
      }
      if (e.type === "user" && e.address === "") {
        throw new Error(
          `delivery: status visibility.allow[${i}] type=user missing address`,
        );
      }
    }
  }
  if (!opts.skipSignatureCheck && m.signature === undefined) {
    throw new Error("delivery: status message missing signature");
  }
}
