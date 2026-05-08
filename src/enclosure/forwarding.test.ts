/**
 * forwarding.compose end-to-end test against the vector.
 *
 * Pull every piece from the pinned outer_enclosure_json (inner
 * plaintext, outer plaintext, original_seal, original_postmark,
 * received_at) and re-compose. Assert the produced bytes match
 * the vector byte-for-byte at every signature.
 *
 * @module
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { marshal } from "../canonical/index.js";
import { composeForwarded } from "./forwarding.js";

function decodeHex(s: string): Uint8Array {
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

describe("enclosure.composeForwarded", () => {
  const dir = findVectorsDir();
  if (dir === null) {
    test.skip("vectors dir missing", () => {});
    return;
  }

  test("3-signature chain reproduces the vector byte-for-byte", () => {
    const file = JSON.parse(
      readFileSync(join(dir, "forwarding.json"), "utf-8"),
    ) as {
      vectors: Array<{
        id: string;
        inputs: Record<string, unknown>;
        expected: Record<string, unknown>;
      }>;
    };
    const v = file.vectors.find((x) => x.id === "forward-valid-three-step-chain");
    if (v === undefined) {
      throw new Error("forward-valid-three-step-chain vector missing");
    }
    const inp = v.inputs;
    const outer = v.expected.outer_enclosure_json as Record<string, unknown>;
    const fromBlock = outer.forwarded_from as Record<string, unknown>;
    const innerSigned = fromBlock.original_enclosure_plaintext as Record<string, unknown>;

    // Pull pre-sign content (everything except sender_signature.value).
    const innerPlaintext = {
      subject: innerSigned.subject as string,
      content_type: innerSigned.content_type as string,
      body: innerSigned.body as Record<string, string>,
      attachments: innerSigned.attachments as unknown[],
      forwarded_from: null,
      extensions: innerSigned.extensions as Record<string, unknown>,
    };
    const outerPlaintext = {
      subject: outer.subject as string,
      content_type: outer.content_type as string,
      body: outer.body as Record<string, string>,
      attachments: outer.attachments as unknown[],
      extensions: outer.extensions as Record<string, unknown>,
    };

    const composed = composeForwarded({
      innerSenderSeed: decodeHex(inp.original_sender_identity_seed_hex as string),
      innerSenderKeyId: inp.original_sender_key_id as string,
      innerEnclosurePlaintext: innerPlaintext,
      forwarderSeed: decodeHex(inp.forwarder_identity_seed_hex as string),
      forwarderKeyId: inp.forwarder_key_id as string,
      outerEnclosurePlaintext: outerPlaintext,
      originalEnvelope: {
        original_seal: fromBlock.original_seal as { algorithm: string; key_id: string },
        original_postmark: fromBlock.original_postmark as Parameters<
          typeof composeForwarded
        >[0]["originalEnvelope"]["original_postmark"],
        original_sender_address: fromBlock.original_sender_address as string,
      },
      receivedAt: fromBlock.received_at as string,
    });

    // Each signature MUST match.
    expect(composed.sender_signature.value).toBe(
      (outer.sender_signature as { value: string }).value,
    );
    expect(composed.forwarded_from.forwarder_attestation.value).toBe(
      (fromBlock.forwarder_attestation as { value: string }).value,
    );
    expect(composed.forwarded_from.original_enclosure_plaintext.sender_signature.value).toBe(
      (innerSigned.sender_signature as { value: string }).value,
    );

    // And the full document must match canonically.
    expect(new TextDecoder().decode(marshal(composed))).toBe(
      new TextDecoder().decode(marshal(outer)),
    );
  });
});
