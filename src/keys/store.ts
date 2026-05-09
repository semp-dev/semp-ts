/**
 * Persistence interfaces and reference in-memory implementation for
 * SEMP key records per KEY.md §4 / §8 / §9.
 *
 * The `KeyStore` interface is the layer-1 contract: it holds public
 * key records (domain + user) and revocation state. `PrivateKeyStore`
 * adds access to the user's own private key material in
 * encrypted-at-rest form per KEY.md §9.1.
 *
 * Server implementations and client implementations have different
 * storage needs but expose the same interfaces so handshake,
 * envelope, and delivery code can be written once.
 *
 * The reference {@link InMemoryKeyStore} is intended for tests,
 * single-process demos, and reference-implementation builds. It is
 * NOT a production storage layer:
 *
 *   - Private keys are held in memory in plaintext (no encryption at
 *     rest, no KDF, no hardware backing). This violates KEY.md §9.1.
 *   - There is no persistence: process restart loses everything.
 *
 * @module
 */

import type { DeviceCertificate } from "./device_certificate.js";
import type { Revocation } from "./key_revocation.js";

/** Key role per KEY.md §1.1. */
export type KeyType = "domain" | "identity" | "encryption" | "device";

/** A single signature entry on a {@link KeyStoreRecord} per KEY.md §5. */
export interface KeyStoreSignature {
  signer: string;
  key_id: string;
  /** Base64 signature bytes. */
  value: string;
  /** ISO 8601 UTC. */
  timestamp: string;
  /** Optional informational tag attached by web-of-trust signers. */
  trust_level?: string;
}

/**
 * A single key record as it appears in a SEMP_KEYS response (KEY.md
 * §4.3, §4.4) or in a domain key publication (KEY.md §2.3).
 */
export interface KeyStoreRecord {
  /** Address (for user keys); empty for domain keys. */
  address?: string;
  key_type: KeyType;
  algorithm: string;
  /** Base64 public key. */
  public_key: string;
  /** Lowercase-hex SHA-256 fingerprint. */
  key_id: string;
  /** ISO 8601 UTC. */
  created: string;
  /**
   * ISO 8601 UTC after which the key SHOULD NOT be used for new
   * operations. Past-expiry keys remain valid for decrypting
   * historical envelopes. Empty / absent for non-expiring keys.
   */
  expires?: string;
  /** Optional set of signatures attached to the record. */
  signatures?: KeyStoreSignature[];
  /** Non-null iff the key has been revoked per KEY.md §8. */
  revocation?: Revocation;
}

/**
 * Persistence interface for SEMP key material. Concrete
 * implementations live in product code; the layer-1 library ships
 * the interface plus {@link InMemoryKeyStore}.
 */
export interface KeyStore {
  /** Look up the current domain key for `domain`, or null. */
  lookupDomainKey(domain: string): KeyStoreRecord | null;
  /**
   * Look up all current key records for `address`, optionally
   * filtered by `keyTypes`. Empty / undefined `keyTypes` means "all
   * known types".
   */
  lookupUserKeys(address: string, keyTypes?: KeyType[]): KeyStoreRecord[];
  /**
   * Persist a fetched key record. Implementations SHOULD respect the
   * record's `expires` timestamp when caching.
   */
  putRecord(rec: KeyStoreRecord): void;
  /**
   * Record a revocation. Subsequent {@link lookupUserKeys} /
   * {@link lookupDomainKey} calls MUST surface the revocation in the
   * returned record per KEY.md §8.
   */
  putRevocation(keyId: string, rev: Revocation): void;
  /**
   * Look up a scoped device certificate by its delegated device's
   * key fingerprint. Returns null when the device is full-access
   * (no certificate is on file).
   */
  lookupDeviceCertificate(deviceKeyId: string): DeviceCertificate | null;
  /** Persist a delegated device certificate. */
  putDeviceCertificate(cert: DeviceCertificate): void;
}

/**
 * Extension that adds access to the user's own private keys. Only
 * client implementations need this; server implementations never
 * hold user private keys (KEY.md §9.1).
 */
export interface PrivateKeyStore extends KeyStore {
  /**
   * Decrypted private key material for `keyId`. Implementations are
   * responsible for prompting the user for unlock credentials when
   * required. Throws when no key is found.
   */
  loadPrivateKey(keyId: string): Uint8Array;
  /**
   * Persist encrypted private key material for `keyId`. Production
   * implementations MUST encrypt at rest using a KDF such as Argon2id
   * (KEY.md §9.2).
   */
  storePrivateKey(keyId: string, privateKey: Uint8Array): void;
}

/**
 * Reference in-memory {@link KeyStore} + {@link PrivateKeyStore}.
 * Tests, demos, and the reference build only.
 */
export class InMemoryKeyStore implements PrivateKeyStore {
  private domainKeys = new Map<string, KeyStoreRecord>();
  private userKeys = new Map<string, KeyStoreRecord[]>();
  private privateKeys = new Map<string, Uint8Array>();
  private deviceCerts = new Map<string, DeviceCertificate>();

  /** Persist a domain record under `domain`. */
  putDomainRecord(domain: string, rec: KeyStoreRecord): void {
    this.domainKeys.set(domain, rec);
  }

  lookupDomainKey(domain: string): KeyStoreRecord | null {
    return this.domainKeys.get(domain) ?? null;
  }

  lookupUserKeys(address: string, keyTypes?: KeyType[]): KeyStoreRecord[] {
    const all = this.userKeys.get(address) ?? [];
    if (keyTypes === undefined || keyTypes.length === 0) {
      return all.slice();
    }
    const want = new Set(keyTypes);
    return all.filter((r) => want.has(r.key_type));
  }

  putRecord(rec: KeyStoreRecord): void {
    if (rec.key_type === "domain") {
      // Domain records are addressed by domain; callers should use
      // putDomainRecord directly. No-op here to match the semp-go
      // reference shape.
      return;
    }
    if (rec.address === undefined || rec.address === "") {
      throw new Error("keys: putRecord on user key requires address");
    }
    const list = this.userKeys.get(rec.address);
    if (list === undefined) {
      this.userKeys.set(rec.address, [rec]);
    } else {
      list.push(rec);
    }
  }

  putRevocation(keyId: string, rev: Revocation): void {
    for (const list of this.userKeys.values()) {
      for (const r of list) {
        if (r.key_id === keyId) {
          r.revocation = rev;
        }
      }
    }
    for (const r of this.domainKeys.values()) {
      if (r.key_id === keyId) {
        r.revocation = rev;
      }
    }
  }

  lookupDeviceCertificate(deviceKeyId: string): DeviceCertificate | null {
    return this.deviceCerts.get(deviceKeyId) ?? null;
  }

  putDeviceCertificate(cert: DeviceCertificate): void {
    // Stored under the delegated device's public-key fingerprint —
    // matches the LookupDeviceCertificate(fp) parameter shape used
    // by the scope-enforcement path. Callers compute the fingerprint
    // from cert.device_public_key.
    if (cert.device_id === "") {
      throw new Error("keys: putDeviceCertificate certificate missing device_id");
    }
    this.deviceCerts.set(cert.device_id, cert);
  }

  loadPrivateKey(keyId: string): Uint8Array {
    const k = this.privateKeys.get(keyId);
    if (k === undefined) {
      throw new Error(`keys: private key ${JSON.stringify(keyId)} not found`);
    }
    return k.slice();
  }

  storePrivateKey(keyId: string, privateKey: Uint8Array): void {
    if (keyId === "") {
      throw new Error("keys: storePrivateKey empty keyId");
    }
    this.privateKeys.set(keyId, privateKey.slice());
  }
}
