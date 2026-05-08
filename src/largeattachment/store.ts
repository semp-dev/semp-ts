/**
 * Operator-side store interface for large-attachment ciphertext
 * blobs per ATTACHMENTS.md §4.2 + §4.3.
 *
 * The store holds the encrypted blobs that envelopes reference by
 * URL. Production deployments wrap S3, GCS, a CDN, etc.; this
 * module ships an in-memory reference for tests + demos.
 *
 * @module
 */

/**
 * Minimal storage interface: `put` an attachment by id;
 * `get` retrieves the bytes; `stat` returns size + presence; `del`
 * removes.
 */
export interface AttachmentStore {
  put(id: string, ciphertext: Uint8Array): Promise<void>;
  get(id: string): Promise<Uint8Array | null>;
  stat(id: string): Promise<{ size: number; present: boolean }>;
  del(id: string): Promise<void>;
}

/** Reference in-memory store. Single-process only. */
export class InMemoryAttachmentStore implements AttachmentStore {
  private readonly blobs = new Map<string, Uint8Array>();

  async put(id: string, ciphertext: Uint8Array): Promise<void> {
    if (id === "") {
      throw new Error("largeattachment: empty id");
    }
    if (this.blobs.has(id)) {
      throw new Error(`largeattachment: blob already stored for ${id}`);
    }
    this.blobs.set(id, ciphertext);
  }

  async get(id: string): Promise<Uint8Array | null> {
    return this.blobs.get(id) ?? null;
  }

  async stat(id: string): Promise<{ size: number; present: boolean }> {
    const blob = this.blobs.get(id);
    if (blob === undefined) {
      return { size: 0, present: false };
    }
    return { size: blob.length, present: true };
  }

  async del(id: string): Promise<void> {
    this.blobs.delete(id);
  }
}
