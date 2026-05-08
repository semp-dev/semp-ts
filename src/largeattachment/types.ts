/**
 * Type definitions for the `semp.dev/large-attachment` extension
 * per ATTACHMENTS.md.
 *
 * Large attachments live as encrypted blobs at HTTPS URLs outside
 * the envelope; the envelope's enclosure carries metadata under
 * the `semp.dev/large-attachment` extension key. Each attachment is
 * encrypted under a key derived from K_enclosure via HKDF-Expand
 * with info `"semp-attachment:" || attachment_id` so any recipient
 * that can decrypt the enclosure can also decrypt every external
 * attachment without additional key wrapping.
 *
 * @module
 */

/** Extension identifier per ATTACHMENTS.md §1.2. */
export const ExtensionKey = "semp.dev/large-attachment";

/**
 * Byte-prefix mixed into HKDF-Expand to derive per-attachment keys
 * per §3.1. The full info input is `HKDFInfoPrefix || attachment_id`.
 */
export const HKDFInfoPrefix = "semp-attachment:";

/** AEAD algorithm identifier for the baseline suite per §3.2. */
export const AEADChaCha20Poly1305 = "chacha20-poly1305";

/** AEAD algorithm identifier for the PQ suite per §3.2. */
export const AEADXChaCha20Poly1305 = "xchacha20-poly1305";

/**
 * Hash algorithm identifier for `ciphertext_hash`. The wire form is
 * `algorithm:hex` per §2.3.
 */
export const HashAlgorithmSHA256 = "sha256";

/** One entry in the large-attachment extension's items array per §2.2. */
export interface Item {
  /** Unique attachment id within the envelope. ULID RECOMMENDED. */
  id: string;
  /** Original filename. MUST NOT contain path separators per §2.3. */
  filename: string;
  /** Plaintext MIME type. */
  mime_type: string;
  /** Plaintext size in bytes. */
  plaintext_size: number;
  /** HTTPS URL the ciphertext is fetched from. */
  url: string;
  /** Digest of the ciphertext bytes, encoded `algorithm:hex`. */
  ciphertext_hash: string;
  /** AEAD algorithm identifier; consistent with the negotiated suite. */
  aead_algorithm: string;
  /** Base64-encoded AEAD nonce. */
  aead_nonce: string;
  /** Non-normative retrieval hints (bearer tokens, range support, …). */
  extensions?: Record<string, unknown>;
}

/** Inner `data` shape of the extension entry per §2.1. */
export interface ExtensionData {
  items: Item[];
}
