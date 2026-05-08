/**
 * migration.compose end-to-end test against the vector. Pulls
 * everything from the pinned signed_record_json + inputs, runs
 * the 4-signature chain, asserts byte equality.
 *
 * @module
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { marshal } from "../canonical/index.js";
import { composeMigrationRecord } from "./migration.js";

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

describe("migration.composeMigrationRecord", () => {
  const dir = findVectorsDir();
  if (dir === null) {
    test.skip("vectors dir missing", () => {});
    return;
  }

  test("4-signature chain reproduces the vector byte-for-byte", () => {
    const file = JSON.parse(
      readFileSync(join(dir, "migration.json"), "utf-8"),
    ) as {
      vectors: Array<{
        id: string;
        inputs: Record<string, unknown>;
        intermediates: Record<string, unknown>;
        expected: Record<string, unknown>;
      }>;
    };
    const v = file.vectors.find((x) => x.id === "migration-cooperative-four-signature-chain");
    if (v === undefined) {
      throw new Error("migration vector missing");
    }
    const inp = v.inputs;
    const sr = v.expected.signed_record_json as Record<string, unknown>;
    const oldIdSig = sr.old_identity_signature as { key_id: string; value: string };
    const newIdSig = sr.new_identity_signature as { key_id: string; value: string };
    const newDomSig = sr.new_domain_signature as { key_id: string; value: string };
    const oldDomSig = sr.old_domain_signature as { key_id: string; value: string };

    const composed = composeMigrationRecord({
      mode: sr.mode as string,
      recordId: sr.record_id as string,
      migratedAt: sr.migrated_at as string,
      forwardingWindowUntil: sr.forwarding_window_until as string,
      oldAddress: sr.old_address as string,
      newAddress: sr.new_address as string,

      oldIdentityKeyId: oldIdSig.key_id,
      oldIdentitySeed: decodeHex(inp.old_identity_seed_hex as string),
      newIdentityKeyId: newIdSig.key_id,
      newIdentityPublicKey: sr.new_identity_public_key as string,
      newIdentitySeed: decodeHex(inp.new_identity_seed_hex as string),
      oldDomainKeyId: oldDomSig.key_id,
      oldDomainSeed: decodeHex(inp.old_domain_seed_hex as string),
      newDomainKeyId: newDomSig.key_id,
      newDomainSeed: decodeHex(inp.new_domain_seed_hex as string),
      extensions: sr.extensions as Record<string, unknown>,
    });

    // Each signature MUST match.
    expect((composed.old_identity_signature as { value: string }).value).toBe(oldIdSig.value);
    expect((composed.new_identity_signature as { value: string }).value).toBe(newIdSig.value);
    expect((composed.new_domain_signature as { value: string }).value).toBe(newDomSig.value);
    expect((composed.old_domain_signature as { value: string }).value).toBe(oldDomSig.value);

    // And the overall structure must match modulo field insertion
    // order (which is what canonical-JSON normalizes away).
    expect(new TextDecoder().decode(marshal(composed))).toBe(
      new TextDecoder().decode(marshal(sr)),
    );
  });
});
