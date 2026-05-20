/**
 * DNS lookup helpers per DISCOVERY.md §2.1 + §2.2 + §7.2.
 *
 * Provides `lookupSRV`, `lookupTXT`, and `lookupMX` wrappers around
 * Node's `node:dns/promises` resolver. Tests inject a custom
 * {@link DNSLookup} implementation.
 *
 * This module is Node-only; `defaultDNSLookup` calls into
 * `node:dns/promises`. Browser / Deno callers must pass a custom
 * {@link DNSLookup} (e.g. backed by DNS-over-HTTPS).
 *
 * @module
 */

import { type TXTCapabilities, parseTXTCapabilities } from "./txt.js";

/**
 * A parsed SEMP SRV record per §2.1. Returned by both
 * {@link lookupSRV} (the standard `_semp._tcp.<domain>` record) and
 * {@link lookupSRVUDP} (the optional `_semp._udp.<domain>` record
 * that operators MAY publish to advertise a distinct QUIC target).
 */
export interface SRVRecord {
  priority: number;
  weight: number;
  port: number;
  target: string;
}

/** A parsed MX record per §7.2. */
export interface MXRecord {
  preference: number;
  exchange: string;
}

/**
 * Narrow DNS interface that {@link lookupSRV} / {@link lookupTXT} /
 * {@link lookupMX} consume. Tests inject a fake; production callers
 * use {@link defaultDNSLookup}.
 */
export interface DNSLookup {
  lookupSRV(domain: string): Promise<SRVRecord[]>;
  lookupTXT(domain: string): Promise<string[]>;
  lookupMX(domain: string): Promise<MXRecord[]>;
}

/**
 * Default DNS lookup backed by Node's `node:dns/promises`. Throws
 * a descriptive error in non-Node environments.
 */
export async function defaultDNSLookup(): Promise<DNSLookup> {
  let dns: typeof import("node:dns/promises");
  try {
    dns = await import("node:dns/promises");
  } catch {
    throw new Error(
      "discovery: node:dns/promises unavailable; pass a DNSLookup explicitly in non-Node environments",
    );
  }
  return {
    async lookupSRV(domain: string): Promise<SRVRecord[]> {
      try {
        const recs = await dns.resolveSrv(domain);
        return recs.map((r) => ({
          priority: r.priority,
          weight: r.weight,
          port: r.port,
          target: r.name.replace(/\.$/, ""),
        }));
      } catch (err) {
        if (isNoData(err) || isNotFound(err)) {
          return [];
        }
        throw err;
      }
    },
    async lookupTXT(domain: string): Promise<string[]> {
      try {
        const recs = await dns.resolveTxt(domain);
        return recs.map((parts) => parts.join(""));
      } catch (err) {
        if (isNoData(err) || isNotFound(err)) {
          return [];
        }
        throw err;
      }
    },
    async lookupMX(domain: string): Promise<MXRecord[]> {
      try {
        const recs = await dns.resolveMx(domain);
        const sorted = [...recs].sort((a, b) => a.priority - b.priority);
        return sorted.map((r) => ({
          preference: r.priority,
          exchange: r.exchange.replace(/\.$/, ""),
        }));
      } catch (err) {
        if (isNoData(err) || isNotFound(err)) {
          return [];
        }
        throw err;
      }
    },
  };
}

function isNoData(err: unknown): boolean {
  return (
    err !== null &&
    typeof err === "object" &&
    "code" in err &&
    (err as { code: string }).code === "ENODATA"
  );
}

function isNotFound(err: unknown): boolean {
  return (
    err !== null &&
    typeof err === "object" &&
    "code" in err &&
    (err as { code: string }).code === "ENOTFOUND"
  );
}

/**
 * Look up `_semp._tcp.<domain>` SRV records and return them in
 * priority-ascending order (clients applying weighted random
 * selection per RFC 2782 sort within a priority group themselves).
 */
export async function lookupSRV(
  domain: string,
  lookup?: DNSLookup,
): Promise<SRVRecord[]> {
  const dns = lookup ?? (await defaultDNSLookup());
  const name = `_semp._tcp.${domain}`;
  const recs = await dns.lookupSRV(name);
  return [...recs].sort((a, b) => a.priority - b.priority);
}

/**
 * Look up the optional `_semp._udp.<domain>` SRV records per §2.1.
 * Operators MAY publish this record when they want to advertise a
 * distinct UDP target for QUIC (different host/port than the TCP
 * target). Clients selecting QUIC MUST prefer it over the
 * `_semp._tcp` target when present. When absent the QUIC endpoint
 * defaults to the `_semp._tcp` target's host:port, which is the
 * common case.
 *
 * Returns an empty array when no `_udp` record is published.
 */
export async function lookupSRVUDP(
  domain: string,
  lookup?: DNSLookup,
): Promise<SRVRecord[]> {
  const dns = lookup ?? (await defaultDNSLookup());
  const name = `_semp._udp.${domain}`;
  const recs = await dns.lookupSRV(name);
  return [...recs].sort((a, b) => a.priority - b.priority);
}

/**
 * Resolve the SRV record a QUIC-capable client should use for
 * `domain`. Prefers the optional `_semp._udp` record when present
 * (operator-specified distinct UDP target). Otherwise falls back to
 * the `_semp._tcp` target's host:port per DISCOVERY.md §2.1.
 *
 * Returns null when neither record exists.
 */
export async function quicTarget(
  domain: string,
  lookup?: DNSLookup,
): Promise<SRVRecord | null> {
  const dns = lookup ?? (await defaultDNSLookup());
  const udp = await lookupSRVUDP(domain, dns);
  if (udp.length > 0) {
    return udp[0] ?? null;
  }
  const tcp = await lookupSRV(domain, dns);
  if (tcp.length > 0) {
    return tcp[0] ?? null;
  }
  return null;
}

/**
 * Look up `_semp._tcp.<domain>` TXT records and return the first
 * one whose `v=` parameter is `semp1`. Returns null when no SEMP
 * TXT record is published.
 */
export async function lookupTXT(
  domain: string,
  lookup?: DNSLookup,
): Promise<TXTCapabilities | null> {
  const dns = lookup ?? (await defaultDNSLookup());
  const name = `_semp._tcp.${domain}`;
  const txts = await dns.lookupTXT(name);
  for (const raw of txts) {
    const cap = parseTXTCapabilities(raw);
    if (cap.v === "semp1") {
      return cap;
    }
  }
  return null;
}

/** Look up MX records for `domain`, sorted by preference ascending. */
export async function lookupMX(
  domain: string,
  lookup?: DNSLookup,
): Promise<MXRecord[]> {
  const dns = lookup ?? (await defaultDNSLookup());
  return dns.lookupMX(domain);
}
