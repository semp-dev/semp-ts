/**
 * SEMP_USER_POLICY wire shape + sign/verify per DELIVERY.md §7.1.
 *
 * Signed by the originating device's identity key under the
 * `SEMP-USER-POLICY:` prefix; the canonical bytes are computed with
 * `signature.value` blanked.
 *
 * @module
 */

import { signSignedDoc, verifySignedDoc } from "../keys/index.js";

/** Wire-level constants per §7.1. */
export const UserPolicyType = "SEMP_USER_POLICY";
export const UserPolicyStep = "update";
export const UserPolicyVersion = "1.0.0";
export const UserPolicyPrefix = "SEMP-USER-POLICY:";

/** Policy operation verb per §7.1. The set is closed; extensibility is via new kinds. */
export type PolicyOp = "add" | "remove" | "modify";

/**
 * Defined policy rule kinds per §7.3. Operators MAY define more
 * via the §7.2 namespaced-identifier rule; the home server rejects
 * unknown kinds with reason_code `policy_kind_unsupported` per §7.2.
 */
export const PolicyKindBlock = "semp.dev/block";
export const PolicyKindAcceptedSender = "semp.dev/accepted_sender";
export const PolicyKindFirstContact = "semp.dev/first_contact";

/** One entry inside {@link UserPolicyMessage.operations} per §7.1. */
export interface PolicyOperation {
  op: PolicyOp;
  kind: string;
  /** For `remove` and `modify` references. */
  entry_id?: string;
  /**
   * For `add` and `modify` carries the new entry shape. Inner shape
   * varies by `kind`.
   */
  entry?: unknown;
}

/** Reusable signature block. */
export interface UserPolicySignatureBlock {
  algorithm: string;
  key_id: string;
  /** Base64. */
  value: string;
}

/** SEMP_USER_POLICY update record per §7.1. */
export interface UserPolicyMessage {
  type: typeof UserPolicyType;
  step: typeof UserPolicyStep;
  version: string;
  user_id: string;
  device_id: string;
  policy_version: number;
  /** ISO 8601 UTC. */
  timestamp: string;
  operations: PolicyOperation[];
  signature: UserPolicySignatureBlock;
}

/**
 * Sign `m.signature` with the originating device's identity private
 * key per §7.1. Mutates `m` in place. Returns the base64 signature.
 */
export function signUserPolicyMessage(
  m: UserPolicyMessage,
  devicePriv: Uint8Array,
  deviceKeyId: string,
): string {
  if (deviceKeyId === "") {
    throw new Error("delivery: empty device key_id");
  }
  // Auto-fill discriminators for caller convenience.
  if ((m.type as string) === "") {
    m.type = UserPolicyType;
  }
  if ((m.step as string) === "") {
    m.step = UserPolicyStep;
  }
  if (m.version === "") {
    m.version = UserPolicyVersion;
  }
  validateUserPolicyMessage(m, { skipSignatureCheck: true });
  m.signature.algorithm = "ed25519";
  m.signature.key_id = deviceKeyId;
  m.signature.value = "";
  const { signedJSON, signatureB64 } = signSignedDoc({
    preSignJSON: m as unknown as Record<string, unknown>,
    seed: devicePriv,
    signaturePath: "signature.value",
    prefix: UserPolicyPrefix,
  });
  m.signature.value = (signedJSON.signature as { value: string }).value;
  return signatureB64;
}

/** Verify `m.signature` against the originating device's identity public key. */
export function verifyUserPolicyMessage(
  m: UserPolicyMessage,
  devicePub: Uint8Array,
): boolean {
  validateUserPolicyMessage(m);
  if (m.signature.value === "") {
    return false;
  }
  const { ok } = verifySignedDoc({
    signedJSON: m as unknown as Record<string, unknown>,
    publicKey: devicePub,
    signaturePath: "signature.value",
    prefix: UserPolicyPrefix,
  });
  return ok;
}

/**
 * Structural validation per §7.1 + the §7.3 op-kind rules.
 *
 * Singleton-shaped kinds (`semp.dev/first_contact`) accept only
 * `modify`; list-shaped kinds accept `add`, `remove`, and `modify`
 * with the entry_id rules in §7.3.
 */
export function validateUserPolicyMessage(
  m: UserPolicyMessage,
  opts: { skipSignatureCheck?: boolean } = {},
): void {
  if (m.type !== UserPolicyType) {
    throw new Error(
      `delivery: user policy type ${JSON.stringify(m.type)}, want ${UserPolicyType}`,
    );
  }
  if (m.step !== UserPolicyStep) {
    throw new Error(
      `delivery: user policy step ${JSON.stringify(m.step)}, want ${UserPolicyStep}`,
    );
  }
  if (m.user_id === "") {
    throw new Error("delivery: user policy missing user_id");
  }
  if (m.device_id === "") {
    throw new Error("delivery: user policy missing device_id");
  }
  if (!Number.isInteger(m.policy_version) || m.policy_version < 1) {
    throw new Error(
      `delivery: user policy policy_version ${m.policy_version} MUST be >= 1`,
    );
  }
  if (typeof m.timestamp !== "string" || m.timestamp === "") {
    throw new Error("delivery: user policy missing timestamp");
  }
  if (Number.isNaN(Date.parse(m.timestamp))) {
    throw new Error("delivery: user policy timestamp is not ISO 8601");
  }
  if (!Array.isArray(m.operations) || m.operations.length === 0) {
    throw new Error("delivery: user policy operations MUST be non-empty");
  }
  for (let i = 0; i < m.operations.length; i++) {
    const op = m.operations[i]!;
    validateOp(op, i);
  }
  if (typeof m.signature?.value !== "string") {
    throw new Error("delivery: user policy signature.value must be a string");
  }
  if (!opts.skipSignatureCheck && m.signature.value === "") {
    throw new Error("delivery: user policy is unsigned");
  }
}

function validateOp(op: PolicyOperation, i: number): void {
  if (op.op !== "add" && op.op !== "remove" && op.op !== "modify") {
    throw new Error(
      `delivery: user policy operations[${i}] op ${JSON.stringify(op.op)} is not in the closed set {add, remove, modify}`,
    );
  }
  if (op.kind === "") {
    throw new Error(`delivery: user policy operations[${i}] missing kind`);
  }
  // Singleton kinds accept only modify per §7.3.
  if (op.kind === PolicyKindFirstContact) {
    if (op.op !== "modify") {
      throw new Error(
        `delivery: user policy operations[${i}] singleton kind ${JSON.stringify(op.kind)} accepts only modify, got ${op.op}`,
      );
    }
    if (op.entry_id !== undefined && op.entry_id !== "") {
      throw new Error(
        `delivery: user policy operations[${i}] singleton kind ${JSON.stringify(op.kind)} MUST NOT carry entry_id`,
      );
    }
    if (op.entry === undefined || op.entry === null) {
      throw new Error(
        `delivery: user policy operations[${i}] singleton kind ${JSON.stringify(op.kind)} modify MUST carry entry`,
      );
    }
  }
  // List-shaped kinds: remove/modify reference by entry_id; add
  // supplies a new entry.
  if (op.op === "remove" && (op.entry_id === undefined || op.entry_id === "")) {
    throw new Error(
      `delivery: user policy operations[${i}] remove op MUST set entry_id`,
    );
  }
  if (op.op === "add" && (op.entry === undefined || op.entry === null)) {
    throw new Error(
      `delivery: user policy operations[${i}] add op MUST carry entry`,
    );
  }
}
