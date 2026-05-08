/**
 * Tests for the handshake message builders. Compose the four signed
 * messages (response, accepted, rejected, plus init/confirm
 * canonical-only) and assert each matches the corresponding vector
 * byte-for-byte at the canonical and signature levels.
 *
 * @module
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { marshal } from "../canonical/index.js";
import {
  buildAccepted,
  buildConfirm,
  buildInit,
  buildRejected,
  buildResponse,
} from "./messages.js";

function decodeHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) {
    throw new Error(`hex length ${s.length} is odd`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function findVectorsDir(): string | null {
  const env = process.env.SEMP_VECTORS_DIR;
  if (env !== undefined && env !== "") {
    return resolve(env);
  }
  const here = fileURLToPath(import.meta.url);
  const candidates = [
    join(dirname(here), "..", "..", "..", "semp-spec", "vectors", "v1.0.0"),
    join(dirname(here), "..", "..", "..", "..", "semp-spec", "vectors", "v1.0.0"),
  ];
  for (const c of candidates) {
    const abs = resolve(c);
    if (existsSync(abs) && statSync(abs).isDirectory()) {
      return abs;
    }
  }
  return null;
}

describe("handshake message builders", () => {
  const dir = findVectorsDir();
  if (dir === null) {
    test.skip("vectors dir missing", () => {});
    return;
  }
  const file = JSON.parse(
    readFileSync(join(dir, "handshake-messages.json"), "utf-8"),
  ) as {
    vectors: Array<{
      id: string;
      inputs: Record<string, unknown>;
      intermediates?: Record<string, unknown>;
      expected?: Record<string, unknown>;
    }>;
  };

  // INIT: canonical-only.
  test("buildInit canonical bytes match vector", () => {
    const v = file.vectors.find((x) => x.id === "handshake-init-canonical");
    if (v === undefined) {
      throw new Error("handshake-init-canonical vector missing");
    }
    const want = v.intermediates?.canonical_utf8 as string | undefined;
    if (want === undefined) {
      return;
    }
    const m = v.inputs.message_json as Record<string, unknown>;
    // Build via the public API using fields from the vector.
    const built = buildInit({
      nonce: m.nonce as string,
      transport: m.transport as string,
      clientEphemeralKey: m.client_ephemeral_key as Record<string, never> as never,
      capabilities: m.capabilities as Record<string, never> as never,
      extensions: m.extensions as Record<string, unknown>,
    });
    expect(new TextDecoder().decode(marshal(built))).toBe(want);
  });

  // CONFIRM: canonical-only.
  test("buildConfirm canonical bytes match vector", () => {
    const v = file.vectors.find((x) => x.id === "handshake-confirm-canonical");
    if (v === undefined) {
      throw new Error("handshake-confirm-canonical vector missing");
    }
    const want = v.intermediates?.canonical_utf8 as string | undefined;
    if (want === undefined) {
      return;
    }
    const m = v.inputs.message_json as Record<string, unknown>;
    const built = buildConfirm({
      sessionId: m.session_id as string,
      confirmationHashB64: m.confirmation_hash as string,
      identityProofB64: m.identity_proof as string,
      extensions: m.extensions as Record<string, unknown>,
    });
    expect(new TextDecoder().decode(marshal(built))).toBe(want);
  });

  // RESPONSE: signed.
  test("buildResponse produces matching signature", () => {
    const v = file.vectors.find((x) => x.id === "handshake-response-signed");
    if (v === undefined) {
      throw new Error("handshake-response-signed vector missing");
    }
    const m = v.inputs.message_pre_sign_json as Record<string, unknown>;
    const built = buildResponse({
      sessionId: m.session_id as string,
      clientNonce: m.client_nonce as string,
      serverNonce: m.server_nonce as string,
      serverEphemeralKey: m.server_ephemeral_key as Record<string, never> as never,
      serverIdentityProof: m.server_identity_proof as Record<string, never> as never,
      negotiated: m.negotiated as Record<string, never> as never,
      serverDomainSigningSeed: decodeHex(v.inputs.server_domain_seed_hex as string),
      extensions: m.extensions as Record<string, unknown>,
    });
    const expected = (v.expected?.signed_message_json ?? {}) as Record<string, unknown>;
    expect(built.server_signature).toBe(expected.server_signature);
  });

  // ACCEPTED: signed.
  test("buildAccepted produces matching signature", () => {
    const v = file.vectors.find((x) => x.id === "handshake-accepted-signed");
    if (v === undefined) {
      throw new Error("handshake-accepted-signed vector missing");
    }
    const m = v.inputs.message_pre_sign_json as Record<string, unknown>;
    const built = buildAccepted({
      sessionId: m.session_id as string,
      sessionTTL: m.session_ttl as number,
      permissions: m.permissions as string[],
      resumptionTicket: m.resumption_ticket as Record<string, never> as never,
      serverDomainSigningSeed: decodeHex(v.inputs.server_domain_seed_hex as string),
      extensions: m.extensions as Record<string, unknown>,
    });
    const expected = (v.expected?.signed_message_json ?? {}) as Record<string, unknown>;
    expect(built.server_signature).toBe(expected.server_signature);
  });

  // REJECTED: signed.
  test("buildRejected produces matching signature", () => {
    const v = file.vectors.find((x) => x.id === "handshake-rejected-signed");
    if (v === undefined) {
      throw new Error("handshake-rejected-signed vector missing");
    }
    const m = v.inputs.message_pre_sign_json as Record<string, unknown>;
    const built = buildRejected({
      sessionId: m.session_id as string,
      reasonCode: m.reason_code as string,
      reason: m.reason as string | undefined,
      serverDomainSigningSeed: decodeHex(v.inputs.server_domain_seed_hex as string),
      extensions: m.extensions as Record<string, unknown>,
    });
    const expected = (v.expected?.signed_message_json ?? {}) as Record<string, unknown>;
    expect(built.server_signature).toBe(expected.server_signature);
  });
});
