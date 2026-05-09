/**
 * User-partitioning strategy per DISCOVERY.md §2.4.
 *
 * Large domains advertise a partition strategy via a
 * `_semp-partition.<domain>` TXT record. Three strategies are
 * defined: `alpha` (split alphabetically), `hash` (SHA-256 mod N),
 * and `lookup` (delegate to a designated partition server).
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { type DNSLookup } from "./dns.js";

/** Partition strategy enum per §2.4. */
export type PartitionStrategy = "alpha" | "hash" | "lookup";

/** Inclusive lowercase ASCII range mapped to a server hostname. */
export interface AlphaRange {
  /** Inclusive starting char code in `[a, z]`. */
  start_char: string;
  /** Inclusive ending char code in `[a, z]`. */
  end_char: string;
  server?: string;
}

/** Parsed `_semp-partition.<domain>` TXT record. */
export interface PartitionConfig {
  /** SEMP partition protocol version. Always `"semp1"` for the initial spec revision. */
  version: string;
  strategy: PartitionStrategy;
  /** Number of partition servers. Used only by `hash`. */
  servers?: number;
  /** Hash algorithm for `hash`. Defaults to `"sha256"` if empty. */
  algorithm?: string;
  /** Domain this config applies to. */
  domain: string;
  /**
   * If non-empty, overrides the default 26-letter mapping for
   * `alpha`. Each entry maps a contiguous range of first-characters
   * to a server hostname. The default mapping splits `a-z` into
   * roughly equal groups of `servers` size and resolves via
   * `_semp-partition-<range>.<domain>` SRV records.
   */
  alpha_ranges?: AlphaRange[];
}

/**
 * Construct the even-split default ranges used by the §2.4 example:
 * 4 ranges covering `a-f`, `g-m`, `n-s`, `t-z` when `servers === 4`.
 * Generalized to any server count `>= 1`.
 */
export function defaultAlphaRanges(servers: number): AlphaRange[] {
  if (servers <= 0) {
    return [];
  }
  if (servers > 26) {
    servers = 26;
  }
  const out: AlphaRange[] = [];
  const charsPerServer = Math.floor(26 / servers);
  const remainder = 26 % servers;
  let start = 0x61; // 'a'
  for (let i = 0; i < servers; i++) {
    let width = charsPerServer;
    if (i < remainder) {
      width += 1;
    }
    let end = start + width - 1;
    if (end > 0x7a) {
      end = 0x7a;
    }
    out.push({
      start_char: String.fromCharCode(start),
      end_char: String.fromCharCode(end),
    });
    start = end + 1;
  }
  return out;
}

/**
 * Callback used by `strategy === "lookup"`. Queries the partition
 * lookup server (published at `_semp-partition-lookup.<domain>` SRV)
 * and returns the hostname of the delivery server that handles
 * `address`. The discovery package does not prescribe the wire
 * format of the lookup query — DISCOVERY.md §2.4 says "the
 * partition server address is published as a separate SRV record"
 * and leaves the query protocol to the implementation.
 */
export type PartitionLookupFunc = (address: string) => Promise<string>;

/** Inputs to {@link resolvePartition}. */
export interface PartitionResolverConfig {
  /**
   * DNS lookup backend. Required for `alpha` and `hash` (to resolve
   * `_semp-partition-<X>.<domain>` SRV records). Unused by
   * `lookup`.
   */
  dns?: DNSLookup;
  /** Required for `strategy === "lookup"`. Ignored otherwise. */
  lookupFunc?: PartitionLookupFunc;
}

/**
 * Return the SEMP server hostname that handles `address` according
 * to `config`.
 *
 *   - `alpha`: extract the first character of the local part, map
 *     it to the range containing it, and return the server for that
 *     range. If `config.alpha_ranges` is empty, resolve via
 *     `_semp-partition-<start>-<end>.<domain>` SRV.
 *   - `hash`: compute `SHA-256(address) mod config.servers` to get
 *     an index, then resolve via `_semp-partition-<index>.<domain>`
 *     SRV.
 *   - `lookup`: delegate to `resolverConfig.lookupFunc`.
 */
export async function resolvePartition(
  config: PartitionConfig,
  resolverConfig: PartitionResolverConfig,
  address: string,
): Promise<string> {
  if (address === "") {
    throw new Error("discovery: empty address");
  }
  switch (config.strategy) {
    case "alpha":
      return resolveAlpha(config, resolverConfig, address);
    case "hash":
      return resolveHash(config, resolverConfig, address);
    case "lookup":
      if (resolverConfig.lookupFunc === undefined) {
        throw new Error("discovery: strategy=lookup requires a lookupFunc");
      }
      return resolverConfig.lookupFunc(address);
    default:
      throw new Error(
        `discovery: unknown partition strategy ${JSON.stringify(config.strategy)}`,
      );
  }
}

async function resolveAlpha(
  config: PartitionConfig,
  resolverConfig: PartitionResolverConfig,
  address: string,
): Promise<string> {
  const local = localPart(address);
  if (local === "") {
    throw new Error("discovery: address has no local part");
  }
  const firstChar = firstLowerChar(local);

  // Fast path: pre-resolved alpha_ranges with non-empty server.
  if (config.alpha_ranges !== undefined && config.alpha_ranges.length > 0) {
    for (const r of config.alpha_ranges) {
      if (
        firstChar >= r.start_char.charCodeAt(0) &&
        firstChar <= r.end_char.charCodeAt(0)
      ) {
        if (r.server !== undefined && r.server !== "") {
          return r.server;
        }
        // Fall through to SRV path with this range's bounds.
        return resolveSRV(
          resolverConfig,
          config.domain,
          `semp-partition-${r.start_char}-${r.end_char}`,
        );
      }
    }
    // Fallback: non-alphabetic first character → last range.
    const last = config.alpha_ranges[config.alpha_ranges.length - 1]!;
    if (last.server !== undefined && last.server !== "") {
      return last.server;
    }
    return resolveSRV(
      resolverConfig,
      config.domain,
      `semp-partition-${last.start_char}-${last.end_char}`,
    );
  }

  // DNS path: construct ranges from defaultAlphaRanges and resolve
  // each range's SRV record.
  const ranges = defaultAlphaRanges(config.servers ?? 0);
  if (ranges.length === 0) {
    throw new Error("discovery: alpha partition requires at least one server");
  }
  let matched = ranges[ranges.length - 1]!; // default to last
  for (const r of ranges) {
    if (
      firstChar >= r.start_char.charCodeAt(0) &&
      firstChar <= r.end_char.charCodeAt(0)
    ) {
      matched = r;
      break;
    }
  }
  return resolveSRV(
    resolverConfig,
    config.domain,
    `semp-partition-${matched.start_char}-${matched.end_char}`,
  );
}

async function resolveHash(
  config: PartitionConfig,
  resolverConfig: PartitionResolverConfig,
  address: string,
): Promise<string> {
  const servers = config.servers ?? 0;
  if (servers <= 0) {
    throw new Error("discovery: hash partition requires servers > 0");
  }
  const sum = sha256(new TextEncoder().encode(address.toLowerCase()));
  // Use the first 8 bytes as a big-endian uint64 for the mod
  // operation. Fits in a safe-integer when `servers` is small.
  let big = 0n;
  for (let i = 0; i < 8; i++) {
    big = (big << 8n) | BigInt(sum[i] ?? 0);
  }
  const idx = big % BigInt(servers);
  return resolveSRV(
    resolverConfig,
    config.domain,
    `semp-partition-${idx.toString()}`,
  );
}

async function resolveSRV(
  resolverConfig: PartitionResolverConfig,
  domain: string,
  service: string,
): Promise<string> {
  if (resolverConfig.dns === undefined) {
    throw new Error("discovery: DNS lookup not configured");
  }
  const name = `_${service}._tcp.${domain}`;
  const records = await resolverConfig.dns.lookupSRV(name);
  if (records.length === 0) {
    throw new Error(`discovery: no SRV records for ${name}`);
  }
  let best = records[0]!;
  for (let i = 1; i < records.length; i++) {
    if (records[i]!.priority < best.priority) {
      best = records[i]!;
    }
  }
  return best.target.replace(/\.$/, "");
}

/** Extract the part before the last `@` in `address`. */
function localPart(address: string): string {
  const i = address.lastIndexOf("@");
  if (i < 0) {
    return address;
  }
  return address.slice(0, i);
}

/**
 * First character of `s` lowercased if it is a lowercase ASCII
 * letter, or `~` (the highest printable ASCII, which sorts after
 * `z`) as a fallback for non-alphabetic first characters. Forces
 * non-alpha users into the last range.
 */
function firstLowerChar(s: string): number {
  if (s.length === 0) {
    return 0x7e; // '~'
  }
  let c = s.charCodeAt(0);
  // We can't see surrogate pairs as anything other than non-alpha;
  // a non-BMP first char hits the fallback below.
  if (c >= 0x41 /* A */ && c <= 0x5a /* Z */) {
    c += 0x61 - 0x41;
  }
  if (c >= 0x61 /* a */ && c <= 0x7a /* z */) {
    return c;
  }
  return 0x7e; // '~'
}

/**
 * Parse a `_semp-partition.<domain>` TXT record value into a
 * {@link PartitionConfig}. The format follows the same
 * semicolon-separated `key=value` convention as the discovery TXT
 * record:
 *
 * ```
 * "v=semp1;strategy=hash;servers=8;algorithm=sha256"
 * ```
 *
 * Unknown keys are silently ignored for forward compatibility.
 */
export function parsePartitionTXT(
  domain: string,
  txt: string,
): PartitionConfig {
  if (txt.trim() === "") {
    throw new Error("discovery: empty partition TXT record");
  }
  const cfg: PartitionConfig = {
    version: "",
    strategy: "alpha",
    domain,
  };
  for (const kv of txt.split(";")) {
    const trimmed = kv.trim();
    const eq = trimmed.indexOf("=");
    if (eq < 0) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    switch (key) {
      case "v":
        cfg.version = val;
        break;
      case "strategy":
        if (val !== "alpha" && val !== "hash" && val !== "lookup") {
          throw new Error(
            `discovery: invalid partition strategy ${JSON.stringify(val)}`,
          );
        }
        cfg.strategy = val;
        break;
      case "servers": {
        let n = 0;
        for (let i = 0; i < val.length; i++) {
          const c = val.charCodeAt(i);
          if (c < 0x30 || c > 0x39) {
            throw new Error(`discovery: invalid servers count ${JSON.stringify(val)}`);
          }
          n = n * 10 + (c - 0x30);
        }
        cfg.servers = n;
        break;
      }
      case "algorithm":
        cfg.algorithm = val;
        break;
      default:
        // unknown key — skip (forward compat).
        break;
    }
  }
  if (cfg.version === "") {
    throw new Error("discovery: partition TXT missing version (v=)");
  }
  // Strategy was defaulted to "alpha"; it must be set explicitly.
  if (!txt.includes("strategy=")) {
    throw new Error("discovery: partition TXT missing strategy");
  }
  return cfg;
}
