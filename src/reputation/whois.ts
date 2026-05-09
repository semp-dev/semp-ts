/**
 * WHOIS hooks per REPUTATION.md §2.1.
 *
 * Operators supply their own WHOIS implementation — there is no de
 * facto WHOIS library that is both reliable and free of rate limits,
 * so this is intentionally pluggable.
 *
 * @module
 */

/**
 * Recommended minimum domain registration age before a domain
 * receives baseline trust per REPUTATION.md §2.1: 30 days, in
 * milliseconds.
 */
export const MinDomainAgeMs = 30 * 24 * 3_600 * 1_000;

/**
 * Pluggable WHOIS lookup. {@link domainAgeMs} returns the age in
 * milliseconds since the domain was first registered.
 */
export interface WHOIS {
  domainAgeMs(domain: string): Promise<number>;
}

/** Whether `ageMs` meets the {@link MinDomainAgeMs} floor. */
export function meetsMinAge(ageMs: number): boolean {
  return ageMs >= MinDomainAgeMs;
}
