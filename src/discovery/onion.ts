/**
 * Tor onion-service domain validation per DISCOVERY.md §2.5.1.
 *
 * v2 onion addresses (16-character labels) are cryptographically
 * deprecated and MUST NOT be used. Only v3 (56-character base32
 * labels) is permitted by the spec.
 *
 * @module
 */

/** The label that marks a Tor onion-service domain. */
export const OnionSuffix = ".onion";

/** Character count of a v3 onion-service identifier (the only permitted version). */
export const OnionV3LabelLength = 56;

/**
 * Whether `d` ends in `.onion`. Case-insensitive per the standard
 * convention for the `.onion` TLD.
 */
export function isOnionDomain(d: string): boolean {
  return d.toLowerCase().endsWith(OnionSuffix);
}

/**
 * Validate `d` as a Tor v3 onion domain. Throws on the first
 * violation; returns nothing on success.
 *
 * Rejects:
 *  - non-`.onion` domains
 *  - empty labels
 *  - v2 (16-char) onion addresses (cryptographically deprecated)
 *  - any other length than 56 chars
 *  - any character outside the v3 base32 alphabet (`a-z` + `2-7`)
 *
 * Multi-label onion domains (`sub.<v3-label>.onion`) are accepted
 * when the rightmost label before `.onion` is the v3 identifier.
 */
export function validateOnionDomain(d: string): void {
  if (!isOnionDomain(d)) {
    throw new Error("discovery: not an .onion domain");
  }
  const lower = d.toLowerCase();
  const trimmed = lower.slice(0, lower.length - OnionSuffix.length);
  if (trimmed === "") {
    throw new Error("discovery: .onion domain has empty label");
  }
  const labels = trimmed.split(".");
  const onionLabel = labels[labels.length - 1] ?? "";
  if (onionLabel.length === 16) {
    throw new Error(
      "discovery: version-2 .onion addresses are not supported; use a v3 address (56-character label)",
    );
  }
  if (onionLabel.length !== OnionV3LabelLength) {
    throw new Error(
      "discovery: .onion label is not a valid v3 identifier (expected 56 characters)",
    );
  }
  for (let i = 0; i < onionLabel.length; i++) {
    const c = onionLabel.charCodeAt(i);
    const isLower = c >= 0x61 /* a */ && c <= 0x7a /* z */;
    const isDigit2to7 = c >= 0x32 /* 2 */ && c <= 0x37 /* 7 */;
    if (!isLower && !isDigit2to7) {
      throw new Error(
        "discovery: .onion label contains characters outside the v3 base32 alphabet",
      );
    }
  }
}
