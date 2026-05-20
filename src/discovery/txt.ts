/**
 * DNS TXT capability-record parsing per DISCOVERY.md §8.1.
 *
 * The TXT record advertises a domain's SEMP capabilities under
 * semicolon-separated `key=value` pairs:
 *
 * ```
 * v=semp1;pq=ready;c=ws,h2,quic;f=groups,threads,reactions
 * ```
 *
 * Known keys:
 *   - `v`  string  protocol version
 *   - `pq` string  PQ readiness signal
 *   - `c`  list    comma-separated transport identifiers
 *   - `f`  list    comma-separated optional features
 *
 * Unknown keys MUST be ignored, not rejected - DNS TXT records are
 * a public surface and an upgrading peer might add new keys before
 * a downgrading peer learns about them.
 *
 * @module
 */

/** Parsed shape of a `_semp.<domain>` TXT record. */
export interface TXTCapabilities {
  v?: string;
  pq?: string;
  c?: string[];
  f?: string[];
  /** Keys present in the record but not recognized by this parser. */
  _ignored_unknown: string[];
}

/**
 * Parse a TXT capability record. Unknown keys are collected into
 * `_ignored_unknown` rather than rejected. Empty segments and
 * malformed `k=v` pairs are silently dropped (DISCOVERY.md §8.1
 * treats DNS TXT as best-effort).
 */
export function parseTXTCapabilities(record: string): TXTCapabilities {
  const out: TXTCapabilities = { _ignored_unknown: [] };
  if (record.length === 0) {
    return out;
  }
  for (const segment of record.split(";")) {
    const trimmed = segment.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq < 1) {
      continue;
    }
    const key = trimmed.slice(0, eq);
    const value = trimmed.slice(eq + 1);
    switch (key) {
      case "v":
        out.v = value;
        break;
      case "pq":
        out.pq = value;
        break;
      case "c":
        out.c = splitCSV(value);
        break;
      case "f":
        out.f = splitCSV(value);
        break;
      default:
        out._ignored_unknown.push(key);
        break;
    }
  }
  return out;
}

function splitCSV(s: string): string[] {
  if (s.length === 0) {
    return [];
  }
  return s.split(",").map((x) => x.trim()).filter((x) => x.length > 0);
}
