/**
 * JSON-driven test-vectors runner.
 *
 * Loads every `*.json` file under `semp-spec/vectors/v1.0.0/` and
 * dispatches each entry to a category-specific handler. Categories
 * without a handler print a `test.skip` with the spec_reference and
 * "handler TODO" so coverage gaps are visible without breaking the
 * build.
 *
 * Path resolution: looks for vectors at `$SEMP_VECTORS_DIR` first,
 * then at `../semp-spec/vectors/v1.0.0/` (the canonical
 * sibling-checkout layout). If neither exists the entire suite is
 * skipped with a clear message.
 *
 * Reference: semp-spec/vectors/README.md.
 */

import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import {
  type VectorEntry,
  bytesEqual,
  decodeHex,
  decodeBase64,
  encodeHex,
  findVectorsDir,
  getBool,
  getField,
  getInt,
  getOptionalString,
  getString,
  isRecord,
  loadVectorFile,
} from "./helpers.js";

import {
  type KDF,
  type SessionKeys,
  computeMAC,
  deriveRekeyKeys,
  deriveSessionKeys,
  newHKDFSHA512,
} from "../../src/crypto/index.js";
import {
  confirmationHash,
  leadingZeroBits,
  verifyChallengeSolution,
} from "../../src/handshake/index.js";

type Handler = (entry: VectorEntry) => void;

/**
 * Dispatch table: each `category` field value maps to its handler.
 * Categories without a handler get a `test.skip` per entry so the
 * coverage gap is visible.
 */
const dispatch: Record<string, Handler> = {
  hkdf: handleHKDF,
  "session-mac": handleSessionMAC,
  "confirmation-hash": handleConfirmationHash,
  pow: handlePoW,
};

const dir = findVectorsDir();

describe("vectors", () => {
  if (dir === null) {
    test.skip("vectors directory not found: set SEMP_VECTORS_DIR or check out semp-spec as a sibling of semp-ts", () => {
      // skipped
    });
    return;
  }

  // eslint-disable-next-line no-console
  console.log(`vectors dir: ${dir}`);

  const files = readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort();

  if (files.length === 0) {
    test.skip("no *.json files in vectors directory", () => {});
    return;
  }

  for (const name of files) {
    const path = join(dir, name);
    describe(name, () => {
      const file = loadVectorFile(path);
      const handler = dispatch[file.category];
      // Cross-reference files like must-reject-index.json don't
      // carry a per-entry `vectors` array; nothing to dispatch.
      if (!Array.isArray(file.vectors) || file.vectors.length === 0) {
        test.skip(`${file.category}: cross-reference file, no per-vector dispatch`, () => {});
        return;
      }
      for (const entry of file.vectors) {
        if (handler === undefined) {
          test.skip(
            `${entry.id} — category "${file.category}" handler TODO (spec ${file.spec_reference})`,
            () => {},
          );
          continue;
        }
        test(entry.id, () => {
          handler(entry);
        });
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Layer 1 handlers

/**
 * HKDF-SHA-512 vectors (VECTORS.md §2). Both `hkdf-baseline` and
 * `hkdf-rekey` share the same shape; they only differ in salt
 * construction (`client_nonce || server_nonce` vs
 * `rekey_nonce || responder_nonce`).
 */
function handleHKDF(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error("hkdf: missing inputs or expected");
  }

  const ikm = decodeHex(getString(inputs, "ikm_hex"));
  let nonce1: Uint8Array;
  let nonce2: Uint8Array;
  const saltConstruction = getOptionalString(inputs, "salt_construction") ?? "";
  if (saltConstruction === "rekey_nonce || responder_nonce") {
    nonce1 = decodeHex(getString(inputs, "rekey_nonce_hex"));
    nonce2 = decodeHex(getString(inputs, "responder_nonce_hex"));
  } else {
    nonce1 = decodeHex(getString(inputs, "client_nonce_hex"));
    nonce2 = decodeHex(getString(inputs, "server_nonce_hex"));
  }

  const kdf: KDF = newHKDFSHA512();

  // Step 1: PRK from Extract.
  const salt = new Uint8Array(nonce1.length + nonce2.length);
  salt.set(nonce1, 0);
  salt.set(nonce2, nonce1.length);
  const gotPRK = kdf.extract(salt, ikm);
  const wantPRK = decodeHex(getString(expected, "prk_hex"));
  expect(encodeHex(gotPRK), "PRK").toBe(encodeHex(wantPRK));

  // Step 2: derived keys.
  const keys: SessionKeys =
    saltConstruction === "rekey_nonce || responder_nonce"
      ? deriveRekeyKeys(kdf, ikm, nonce1, nonce2)
      : deriveSessionKeys(kdf, ikm, nonce1, nonce2);

  const expectedKeys = getField(expected, "keys");
  if (!isRecord(expectedKeys)) {
    throw new Error("hkdf: expected.keys missing");
  }
  checkSessionKey("K_enc_c2s", keys.encC2S, expectedKeys);
  checkSessionKey("K_enc_s2c", keys.encS2C, expectedKeys);
  checkSessionKey("K_mac_c2s", keys.macC2S, expectedKeys);
  checkSessionKey("K_mac_s2c", keys.macS2C, expectedKeys);
  checkSessionKey("K_env_mac", keys.envMAC, expectedKeys);
}

function checkSessionKey(name: string, got: Uint8Array, expected: unknown): void {
  const field = `${name}_hex`;
  const want = getString(expected, field);
  expect(encodeHex(got), name).toBe(want);
}

/**
 * HMAC-SHA-256 over canonical envelope bytes (VECTORS.md §6). The
 * vector pins the canonical UTF-8 string directly so the MAC is
 * testable without re-canonicalizing an envelope here.
 */
function handleSessionMAC(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error("session-mac: missing inputs or expected");
  }

  const key = decodeHex(getString(inputs, "key_hex"));
  const message = new TextEncoder().encode(
    getString(inputs, "message_canonical_utf8"),
  );
  const got = computeMAC(key, message);
  const want = decodeHex(getString(expected, "mac_hex"));
  expect(encodeHex(got)).toBe(encodeHex(want));
}

/**
 * Confirmation hash (VECTORS.md §5). SHA-256 over the canonical
 * bytes of message_1 (init) and message_2 (response).
 */
function handleConfirmationHash(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error("confirmation-hash: missing inputs or expected");
  }

  const m1 = new TextEncoder().encode(
    getString(inputs, "message_1_canonical_utf8"),
  );
  const m2 = new TextEncoder().encode(
    getString(inputs, "message_2_canonical_utf8"),
  );
  const got = confirmationHash(m1, m2);
  const want = decodeHex(getString(expected, "hash_hex"));
  expect(encodeHex(got)).toBe(encodeHex(want));
}

/**
 * Challenge-PoW vectors (VECTORS.md §4). Verify the solution
 * against the input difficulty; cross-check leadingZeroBits.
 */
function handlePoW(entry: VectorEntry): void {
  const inputs = entry.inputs;
  const expected = entry.expected;
  if (!isRecord(inputs) || !isRecord(expected)) {
    throw new Error("pow: missing inputs or expected");
  }

  const prefix = decodeHex(getString(inputs, "prefix_hex"));
  const challengeId = getString(inputs, "challenge_id");
  const nonceB64 = getString(inputs, "nonce_b64");
  const difficulty = getInt(inputs, "required_difficulty_bits");
  const wantHashHex = getString(expected, "hash_hex");
  const wantValid = getBool(expected, "valid");

  const err = verifyChallengeSolution(
    prefix,
    challengeId,
    nonceB64,
    wantHashHex,
    difficulty,
  );
  const gotValid = err === null;
  expect(gotValid, `valid (err=${err?.message ?? ""})`).toBe(wantValid);

  // Cross-check LeadingZeroBits independently so a regression in
  // either path is localizable.
  const wantLZ = getInt(expected, "leading_zero_bits");
  const hashBytes = decodeHex(wantHashHex);
  expect(leadingZeroBits(hashBytes)).toBe(wantLZ);
  // Quiet unused-import lint if any: bytesEqual + decodeBase64 are
  // re-exports the runner uses in later waves.
  void bytesEqual;
  void decodeBase64;
}
