/**
 * Identity-proof composition per HANDSHAKE.md §2.5.
 *
 * The client's CONFIRM message carries an encrypted identity-proof
 * block — a self-contained JSON object proving control of the
 * client's long-term identity key, encrypted under the freshly
 * derived `K_enc_c2s` so a passive observer sees only opaque
 * ciphertext.
 *
 * Construction:
 *
 *   1. signed_input = "SEMP-IDENTITY:" || session_id || confirmation_hash
 *   2. identity_signature = Ed25519(client_long_term_seed, signed_input)
 *   3. block = {
 *        client_id, client_identity, client_long_term_key_id,
 *        identity_signature: base64(...),
 *        auth: { method: "identity_key", params: {} }
 *      }
 *   4. nonce = 12 fresh bytes (or caller-pinned for vectors)
 *   5. aead_ct = ChaCha20-Poly1305(K_enc_c2s, nonce, JSON(block), AAD=session_id_utf8)
 *   6. wrapped = nonce || aead_ct
 *   7. identity_proof = base64(wrapped)
 *
 * The verify path on the server side reverses this.
 *
 * @module
 */

import { aeadOpen, aeadSeal } from "../crypto/index.js";
import { sign as ed25519Sign } from "../keys/index.js";

/** Domain-separation prefix per ENVELOPE.md §4.3. */
export const IdentityPrefix = "SEMP-IDENTITY:";

/** Inputs to {@link composeIdentityProof}. */
export interface ComposeIdentityProofInput {
  /** Client identifier (ULID RECOMMENDED). */
  clientId: string;
  /** Full address, `user@domain`. */
  clientIdentity: string;
  /** 32-byte Ed25519 secret seed for the client's long-term identity key. */
  clientLongTermSeed: Uint8Array;
  /** Fingerprint of the long-term public key. */
  clientLongTermKeyId: string;
  /** Session id from RESPONSE. */
  sessionId: string;
  /** 32-byte confirmation hash from {@link "./confirm".confirmationHash}. */
  confirmationHash: Uint8Array;
  /** Session direction key for client -> server traffic. */
  encC2S: Uint8Array;
  /**
   * Authentication method block. Defaults to
   * `{ method: "identity_key", params: {} }` per §2.6.
   */
  auth?: { method: string; params: Record<string, unknown> };
  /**
   * 12-byte AEAD nonce. Production callers omit this and let the
   * function source fresh entropy; tests pin it for byte-level
   * reproducibility.
   */
  proofNonce?: Uint8Array;
}

/** Decrypted shape of the identity-proof block. */
export interface IdentityProofBlock {
  client_id: string;
  client_identity: string;
  client_long_term_key_id: string;
  identity_signature: string;
  auth: { method: string; params: Record<string, unknown> };
}

/**
 * Build the encrypted identity_proof string for CONFIRM. Returns
 * the base64-encoded `nonce || aead_ct` ready to splice into
 * `confirm.identity_proof`.
 */
export function composeIdentityProof(input: ComposeIdentityProofInput): {
  identityProofB64: string;
  block: IdentityProofBlock;
  nonce: Uint8Array;
} {
  // Step 1+2: identity signature over prefix || session_id || confirmation_hash.
  const sessionIdBytes = new TextEncoder().encode(input.sessionId);
  const signed = concat(
    new TextEncoder().encode(IdentityPrefix),
    concat(sessionIdBytes, input.confirmationHash),
  );
  const identitySig = ed25519Sign(input.clientLongTermSeed, signed);

  // Step 3: assemble block.
  const block: IdentityProofBlock = {
    client_id: input.clientId,
    client_identity: input.clientIdentity,
    client_long_term_key_id: input.clientLongTermKeyId,
    identity_signature: base64Encode(identitySig),
    auth: input.auth ?? { method: "identity_key", params: {} },
  };
  const blockBytes = new TextEncoder().encode(JSON.stringify(block));

  // Step 4-7: AEAD-Seal with K_enc_c2s, AAD = session_id UTF-8 bytes.
  const nonce = input.proofNonce ?? randomBytes(12);
  if (nonce.length !== 12) {
    throw new Error(`composeIdentityProof: proofNonce must be 12 bytes, got ${nonce.length}`);
  }
  const ct = aeadSeal("chacha20-poly1305", input.encC2S, nonce, blockBytes, sessionIdBytes);
  const wrapped = concat(nonce, ct);
  return {
    identityProofB64: base64Encode(wrapped),
    block,
    nonce,
  };
}

/** Inputs to {@link openIdentityProof} (the server-side inverse). */
export interface OpenIdentityProofInput {
  /** The base64 string from confirm.identity_proof. */
  identityProofB64: string;
  /** Session direction key for client -> server (server holds this too). */
  encC2S: Uint8Array;
  /** Session id from RESPONSE (used as AAD). */
  sessionId: string;
}

/**
 * Decrypt an identity_proof string produced by
 * {@link composeIdentityProof}. Returns the parsed block on
 * success; throws on AEAD failure or invalid base64.
 *
 * The caller MUST further verify the inner identity_signature
 * against the client_long_term_key_id's public key over
 * `SEMP-IDENTITY: || session_id || confirmation_hash`.
 */
export function openIdentityProof(input: OpenIdentityProofInput): IdentityProofBlock {
  const wrapped = base64Decode(input.identityProofB64);
  if (wrapped.length < 12) {
    throw new Error("openIdentityProof: identity_proof too short");
  }
  const nonce = wrapped.slice(0, 12);
  const ct = wrapped.slice(12);
  const aad = new TextEncoder().encode(input.sessionId);
  const pt = aeadOpen("chacha20-poly1305", input.encC2S, nonce, ct, aad);
  const block = JSON.parse(new TextDecoder().decode(pt)) as IdentityProofBlock;
  return block;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function base64Encode(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
}

function base64Decode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}
