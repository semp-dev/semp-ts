/**
 * envelope.compose / envelope.openForRecipient round-trip test.
 *
 * Validates the production compose API against the
 * envelope-roundtrip-baseline-single-recipient vector. The vector
 * pins every input the deterministic compose path needs (postmark
 * fields, K_brief, K_enclosure, AEAD nonces, ephemeral wrap
 * randomness, signing seed, MAC key); we feed them in and assert
 * the produced envelope matches what the spec generator produced
 * byte-for-byte at every layer (signature, MAC, brief, enclosure,
 * each wrapped recipient slot).
 *
 * @module
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { type WrapRandomness } from "../seal/index.js";
import { compose, openForRecipient } from "./compose.js";

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

describe("envelope.compose", () => {
  const dir = findVectorsDir();
  if (dir === null) {
    test.skip("vectors dir missing", () => {});
    return;
  }

  test("baseline single-recipient round-trip matches the pinned envelope", () => {
    const file = JSON.parse(
      readFileSync(join(dir, "envelope-roundtrip.json"), "utf-8"),
    ) as { vectors: Array<{ id: string; inputs: Record<string, unknown>; expected: Record<string, unknown> }> };
    const v = file.vectors.find((x) => x.id === "envelope-roundtrip-baseline-single-recipient");
    if (v === undefined) {
      throw new Error("baseline envelope-roundtrip vector missing");
    }
    const inp = v.inputs;
    const exp = v.expected;

    const wrapRandomness = new Map<string, WrapRandomness>();
    // The vector pins three ephemeral X25519 private keys: one for
    // each recipient slot. The runner-side ephemeral_priv_brief_for_*
    // / ephemeral_priv_enclosure_for_* fields are exactly those.
    wrapRandomness.set(inp.recipient_client_key_id as string, {
      ephemeralX25519Priv: decodeHex(inp.ephemeral_priv_brief_for_client_hex as string),
    });
    wrapRandomness.set(inp.recipient_server_domain_key_id as string, {
      ephemeralX25519Priv: decodeHex(inp.ephemeral_priv_brief_for_domain_hex as string),
    });
    wrapRandomness.set(`enclosure:${inp.recipient_client_key_id as string}`, {
      ephemeralX25519Priv: decodeHex(inp.ephemeral_priv_enclosure_for_client_hex as string),
    });

    // Postmark fields aren't pinned individually — pull them from
    // the expected envelope so the test focuses on computed bytes
    // (signature, MAC, ciphertext, wraps) rather than trivially
    // copied scalars.
    const expectedEnvForInputs = exp.envelope_json as Record<string, unknown>;
    const expectedPostmarkForInputs = expectedEnvForInputs.postmark as Record<string, unknown>;

    const composed = compose({
      suite: "x25519-chacha20-poly1305",
      sealKeyId: inp.sender_domain_signing_key_id as string,
      senderDomainSigningSeed: decodeHex(inp.sender_domain_signing_seed_hex as string),
      postmark: {
        id: expectedPostmarkForInputs.id as string,
        session_id: expectedPostmarkForInputs.session_id as string,
        from_domain: expectedPostmarkForInputs.from_domain as string,
        to_domain: expectedPostmarkForInputs.to_domain as string,
        expires: expectedPostmarkForInputs.expires as string,
      },
      briefPlaintext: inp.brief_pre_encrypt_json,
      enclosurePlaintext: inp.enclosure_post_sign_json,
      briefRecipients: [
        {
          keyId: inp.recipient_server_domain_key_id as string,
          publicKey: decodeHex(inp.recipient_server_domain_pub_hex as string),
        },
        {
          keyId: inp.recipient_client_key_id as string,
          publicKey: decodeHex(inp.recipient_client_pub_hex as string),
        },
      ],
      enclosureRecipients: [
        {
          keyId: inp.recipient_client_key_id as string,
          publicKey: decodeHex(inp.recipient_client_pub_hex as string),
        },
      ],
      kBrief: decodeHex(inp.K_brief_hex as string),
      kEnclosure: decodeHex(inp.K_enclosure_hex as string),
      kEnvMAC: decodeHex(inp.K_env_mac_hex as string),
      briefAEADNonce: decodeHex(inp.brief_aead_nonce_hex as string),
      enclosureAEADNonce: decodeHex(inp.enclosure_aead_nonce_hex as string),
      wrapRandomness,
    });

    // Pull the vector's pinned envelope and replicate the postmark
    // fields the test couldn't infer above, so the comparison is
    // about the COMPUTED bytes not the trivially-copied ones.
    const expectedEnv = exp.envelope_json as Record<string, unknown>;
    const expectedPostmark = expectedEnv.postmark as Record<string, unknown>;
    expect(composed.postmark.id).toBe(expectedPostmark.id);
    expect(composed.postmark.session_id).toBe(expectedPostmark.session_id);

    // Brief / enclosure ciphertexts MUST match.
    expect(composed.brief).toBe(expectedEnv.brief);
    expect(composed.enclosure).toBe(expectedEnv.enclosure);

    // Each per-recipient wrap MUST match.
    const expectedSeal = expectedEnv.seal as Record<string, unknown>;
    expect(composed.seal.brief_recipients).toEqual(expectedSeal.brief_recipients);
    expect(composed.seal.enclosure_recipients).toEqual(expectedSeal.enclosure_recipients);

    // seal.signature and seal.session_mac MUST match.
    expect(composed.seal.signature).toBe(expectedSeal.signature);
    expect(composed.seal.session_mac).toBe(expectedSeal.session_mac);

    // openForRecipient round-trips back to the original brief and
    // enclosure bytes.
    const opened = openForRecipient({
      suite: "x25519-chacha20-poly1305",
      envelope: composed,
      recipientKeyId: inp.recipient_client_key_id as string,
      recipientPrivateKey: decodeHex(inp.recipient_client_priv_hex as string),
      recipientPublicKey: decodeHex(inp.recipient_client_pub_hex as string),
    });
    expect(opened.brief).toEqual(inp.brief_pre_encrypt_json);
    expect(opened.enclosure).toEqual(inp.enclosure_post_sign_json);
  });
});
