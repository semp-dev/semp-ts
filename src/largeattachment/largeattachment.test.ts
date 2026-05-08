/**
 * Large-attachment tests. Cover encrypt/decrypt round-trip for both
 * baseline + PQ suites, ciphertext-hash binding, AAD-tampering
 * rejection, URL validation, and extension-map helpers.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import {
  CiphertextHashMismatchError,
  ExtensionKey,
  type Item,
  appendToExtensions,
  ciphertextHash,
  decryptAttachment,
  deriveAttachmentKey,
  encryptAttachment,
  findById,
  readFromExtensions,
  removeFromExtensions,
  setOnExtensions,
  validateItem,
  validateUrl,
  verifyCiphertextHash,
} from "./index.js";

function deterministicKey(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

describe("deriveAttachmentKey", () => {
  test("produces 32 bytes deterministic from (kEnclosure, id)", () => {
    const k1 = deriveAttachmentKey(deterministicKey(0xab), "att-1", 32);
    const k2 = deriveAttachmentKey(deterministicKey(0xab), "att-1", 32);
    expect(k1).toEqual(k2);
    expect(k1.length).toBe(32);
  });

  test("different ids produce different keys", () => {
    const k1 = deriveAttachmentKey(deterministicKey(0xab), "att-1", 32);
    const k2 = deriveAttachmentKey(deterministicKey(0xab), "att-2", 32);
    expect(k1).not.toEqual(k2);
  });

  test("different K_enclosure values produce different keys", () => {
    const k1 = deriveAttachmentKey(deterministicKey(0xab), "att-1", 32);
    const k2 = deriveAttachmentKey(deterministicKey(0xcd), "att-1", 32);
    expect(k1).not.toEqual(k2);
  });

  test("rejects invalid inputs", () => {
    expect(() => deriveAttachmentKey(new Uint8Array(0), "x", 32)).toThrow(/empty/);
    expect(() => deriveAttachmentKey(deterministicKey(1), "", 32)).toThrow(/attachment_id/);
    expect(() => deriveAttachmentKey(deterministicKey(1), "x", 0)).toThrow(/length/);
  });
});

describe("ciphertextHash + verifyCiphertextHash", () => {
  test("hash round-trips", () => {
    const ct = new TextEncoder().encode("ciphertext");
    const h = ciphertextHash(ct);
    expect(h.startsWith("sha256:")).toBe(true);
    const item: Item = {
      id: "x",
      filename: "f.txt",
      mime_type: "text/plain",
      plaintext_size: 0,
      url: "https://semp.example.com/blobs/x",
      ciphertext_hash: h,
      aead_algorithm: "chacha20-poly1305",
      aead_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    };
    expect(verifyCiphertextHash(item, ct)).toBe(true);
  });

  test("tampered ciphertext fails hash check", () => {
    const ct = new TextEncoder().encode("ciphertext");
    const item: Item = {
      id: "x",
      filename: "f.txt",
      mime_type: "text/plain",
      plaintext_size: 0,
      url: "https://semp.example.com/blobs/x",
      ciphertext_hash: ciphertextHash(ct),
      aead_algorithm: "chacha20-poly1305",
      aead_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    };
    const tampered = new Uint8Array(ct);
    tampered[0] = (tampered[0]! ^ 0xff) & 0xff;
    expect(verifyCiphertextHash(item, tampered)).toBe(false);
  });

  test("unsupported hash algorithm rejected", () => {
    const ct = new TextEncoder().encode("ciphertext");
    const item: Item = {
      id: "x",
      filename: "f.txt",
      mime_type: "text/plain",
      plaintext_size: 0,
      url: "https://semp.example.com/blobs/x",
      ciphertext_hash: "sha512:00",
      aead_algorithm: "chacha20-poly1305",
      aead_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    };
    expect(verifyCiphertextHash(item, ct)).toBe(false);
  });
});

describe("validateUrl", () => {
  test("accepts https FQDN", () => {
    validateUrl("https://semp.example.com/blob/x");
  });

  test("accepts IPv6 literal in brackets", () => {
    validateUrl("https://[::1]/blob/x");
  });

  test("rejects http", () => {
    expect(() => validateUrl("http://example.com/x")).toThrow(/https/);
  });

  test("rejects bare IPv4", () => {
    expect(() => validateUrl("https://1.2.3.4/x")).toThrow(/IPv4/);
  });

  test("rejects single-label hostname", () => {
    expect(() => validateUrl("https://localhost/x")).toThrow(/fully qualified/);
  });

  test("rejects empty url", () => {
    expect(() => validateUrl("")).toThrow(/empty/);
  });
});

describe("validateItem", () => {
  function happyItem(): Item {
    return {
      id: "att-1",
      filename: "report.pdf",
      mime_type: "application/pdf",
      plaintext_size: 12345,
      url: "https://semp.example.com/blobs/att-1",
      ciphertext_hash: "sha256:" + "0".repeat(64),
      aead_algorithm: "chacha20-poly1305",
      aead_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    };
  }

  test("happy path", () => {
    validateItem(happyItem());
  });

  test("rejects path separators in filename", () => {
    const i = happyItem();
    i.filename = "../etc/passwd";
    expect(() => validateItem(i)).toThrow(/path separator/);
  });

  test("rejects negative plaintext_size", () => {
    const i = happyItem();
    i.plaintext_size = -1;
    expect(() => validateItem(i)).toThrow(/plaintext_size/);
  });
});

describe("encrypt + decrypt round-trip (baseline suite)", () => {
  test("plaintext recovered exactly", () => {
    const kEnc = deterministicKey(0xab);
    const plaintext = new TextEncoder().encode("hello attachment");
    const { item, ciphertext } = encryptAttachment({
      suite: "x25519-chacha20-poly1305",
      kEnclosure: kEnc,
      plaintext,
      filename: "hello.txt",
      mimeType: "text/plain",
      url: "https://semp.example.com/blobs/x",
    });
    expect(item.aead_algorithm).toBe("chacha20-poly1305");
    expect(item.plaintext_size).toBe(plaintext.length);

    const decoded = decryptAttachment(
      "x25519-chacha20-poly1305",
      kEnc,
      item,
      ciphertext,
    );
    expect(decoded).toEqual(plaintext);
  });

  test("tampered ciphertext throws CiphertextHashMismatchError", () => {
    const kEnc = deterministicKey(0xab);
    const { item, ciphertext } = encryptAttachment({
      suite: "x25519-chacha20-poly1305",
      kEnclosure: kEnc,
      plaintext: new Uint8Array([1, 2, 3]),
      filename: "f.bin",
      mimeType: "application/octet-stream",
      url: "https://semp.example.com/blobs/x",
    });
    const tampered = new Uint8Array(ciphertext);
    tampered[0] = (tampered[0]! ^ 0xff) & 0xff;
    expect(() =>
      decryptAttachment("x25519-chacha20-poly1305", kEnc, item, tampered),
    ).toThrow(CiphertextHashMismatchError);
  });

  test("tampered metadata (filename) breaks AEAD open", () => {
    const kEnc = deterministicKey(0xab);
    const { item, ciphertext } = encryptAttachment({
      suite: "x25519-chacha20-poly1305",
      kEnclosure: kEnc,
      plaintext: new Uint8Array([1, 2, 3]),
      filename: "original.txt",
      mimeType: "text/plain",
      url: "https://semp.example.com/blobs/x",
    });
    const tampered = { ...item, filename: "evil.txt" };
    expect(() =>
      decryptAttachment("x25519-chacha20-poly1305", kEnc, tampered, ciphertext),
    ).toThrow();
  });

  test("decrypt under wrong K_enclosure fails AEAD open", () => {
    const kEnc = deterministicKey(0xab);
    const { item, ciphertext } = encryptAttachment({
      suite: "x25519-chacha20-poly1305",
      kEnclosure: kEnc,
      plaintext: new Uint8Array([1, 2, 3]),
      filename: "f.bin",
      mimeType: "application/octet-stream",
      url: "https://semp.example.com/blobs/x",
    });
    const wrong = deterministicKey(0xcd);
    expect(() =>
      decryptAttachment("x25519-chacha20-poly1305", wrong, item, ciphertext),
    ).toThrow();
  });
});

describe("encrypt + decrypt round-trip (PQ suite uses XChaCha20-Poly1305)", () => {
  test("nonce is 24 bytes; plaintext recovered", () => {
    const kEnc = deterministicKey(0x42);
    const plaintext = new TextEncoder().encode("pq attachment");
    const { item, ciphertext } = encryptAttachment({
      suite: "pq-kyber768-x25519",
      kEnclosure: kEnc,
      plaintext,
      filename: "pq.txt",
      mimeType: "text/plain",
      url: "https://semp.example.com/blobs/pq",
    });
    expect(item.aead_algorithm).toBe("xchacha20-poly1305");
    const nonce = Buffer.from(item.aead_nonce, "base64");
    expect(nonce.length).toBe(24);

    const decoded = decryptAttachment(
      "pq-kyber768-x25519",
      kEnc,
      item,
      ciphertext,
    );
    expect(decoded).toEqual(plaintext);
  });

  test("suite mismatch on decrypt is rejected", () => {
    const kEnc = deterministicKey(0xab);
    const { item, ciphertext } = encryptAttachment({
      suite: "x25519-chacha20-poly1305",
      kEnclosure: kEnc,
      plaintext: new Uint8Array([1]),
      filename: "f.bin",
      mimeType: "application/octet-stream",
      url: "https://semp.example.com/blobs/x",
    });
    expect(() =>
      decryptAttachment("pq-kyber768-x25519", kEnc, item, ciphertext),
    ).toThrow(/aead_algorithm/);
  });
});

describe("extensions helpers", () => {
  function fakeItem(id: string): Item {
    return {
      id,
      filename: `${id}.txt`,
      mime_type: "text/plain",
      plaintext_size: 1,
      url: "https://semp.example.com/blobs/" + id,
      ciphertext_hash: "sha256:" + "0".repeat(64),
      aead_algorithm: "chacha20-poly1305",
      aead_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    };
  }

  test("readFromExtensions: empty / absent yields []", () => {
    expect(readFromExtensions(undefined)).toEqual([]);
    expect(readFromExtensions({})).toEqual([]);
  });

  test("readFromExtensions: malformed throws", () => {
    expect(() =>
      readFromExtensions({ [ExtensionKey]: "not-an-object" }),
    ).toThrow();
    expect(() =>
      readFromExtensions({ [ExtensionKey]: { data: "not-an-object" } }),
    ).toThrow();
    expect(() =>
      readFromExtensions({ [ExtensionKey]: { data: { items: "not-array" } } }),
    ).toThrow();
  });

  test("setOnExtensions / readFromExtensions round-trip", () => {
    const items = [fakeItem("a"), fakeItem("b")];
    const ext = setOnExtensions(undefined, items);
    expect(readFromExtensions(ext)).toEqual(items);
  });

  test("setOnExtensions with empty list removes the entry", () => {
    const ext = setOnExtensions({ [ExtensionKey]: { data: { items: [fakeItem("a")] } } }, []);
    expect(ext[ExtensionKey]).toBeUndefined();
  });

  test("appendToExtensions preserves existing items", () => {
    const ext1 = setOnExtensions(undefined, [fakeItem("a")]);
    const ext2 = appendToExtensions(ext1, [fakeItem("b")]);
    const out = readFromExtensions(ext2);
    expect(out.map((i) => i.id)).toEqual(["a", "b"]);
  });

  test("removeFromExtensions drops the entry", () => {
    const ext = setOnExtensions(undefined, [fakeItem("a")]);
    const cleared = removeFromExtensions(ext);
    expect(readFromExtensions(cleared)).toEqual([]);
  });

  test("findById finds and misses cleanly", () => {
    const ext = setOnExtensions(undefined, [fakeItem("a"), fakeItem("b")]);
    expect(findById(ext, "a")?.id).toBe("a");
    expect(findById(ext, "ghost")).toBeNull();
  });
});
