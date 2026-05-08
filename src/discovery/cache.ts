/**
 * Discovery result cache per DISCOVERY.md §6.1 + §7.3.
 *
 * Resolvers consult the cache before any DNS / HTTPS lookup and
 * write fresh results back with the TTL declared by the source.
 * Implementations MUST respect TTLs, invalidate entries on
 * delivery failure, and encrypt cached results at rest where
 * feasible (the in-memory reference does NOT encrypt; production
 * deployments wrap a durable encrypted backend).
 *
 * @module
 */

/** Default TTLs when the source declines to declare one. */
export const DefaultTTLSEMPMs = 60 * 60 * 1000; // 1 hour
export const DefaultTTLLegacyMs = 24 * 60 * 60 * 1000; // 24 hours
export const DefaultTTLNotFoundMs = 60 * 60 * 1000; // 1 hour

/**
 * Discovery result cache interface.
 *
 * Keys are normalized by the cache implementation (lowercased) so
 * that case-equivalent addresses share an entry.
 */
export interface DiscoveryCache<T> {
  get(address: string): Promise<T | null>;
  put(address: string, value: T, ttlMs: number): Promise<void>;
  invalidate(address: string): Promise<void>;
}

/** Reference in-memory {@link DiscoveryCache}. Single-process only. */
export class InMemoryDiscoveryCache<T> implements DiscoveryCache<T> {
  private readonly entries = new Map<string, { value: T; expiresAt: number }>();
  private readonly nowFn: () => Date;

  constructor(nowFn: () => Date = () => new Date()) {
    this.nowFn = nowFn;
  }

  async get(address: string): Promise<T | null> {
    const k = address.toLowerCase();
    const entry = this.entries.get(k);
    if (entry === undefined) {
      return null;
    }
    if (entry.expiresAt > 0 && this.nowFn().getTime() > entry.expiresAt) {
      this.entries.delete(k);
      return null;
    }
    return entry.value;
  }

  async put(address: string, value: T, ttlMs: number): Promise<void> {
    const k = address.toLowerCase();
    const expiresAt = ttlMs > 0 ? this.nowFn().getTime() + ttlMs : 0;
    this.entries.set(k, { value, expiresAt });
  }

  async invalidate(address: string): Promise<void> {
    this.entries.delete(address.toLowerCase());
  }
}
