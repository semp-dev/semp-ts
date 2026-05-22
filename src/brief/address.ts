/**
 * SEMP user address per ENVELOPE.md §2.3.
 *
 * The wire form is `local-part@domain`:
 *   - Local-part: Unicode NFC, case-sensitive on the wire, ≤64 bytes.
 *   - Domain: A-label (Punycode) per IDNA2008, ASCII-only, lowercase
 *     on the wire, ≤253 bytes, ≤63 bytes per DNS label.
 *
 * {@link validateAddress} enforces the canonical form at ingress;
 * {@link canonicalizeAddress} converts possibly-denormalized input
 * (mixed-case domain, U-label domain, non-NFC local-part) to the
 * canonical wire form.
 *
 * IDNA2008 conversion uses the `tr46` package (the WHATWG/UTS #46
 * reference implementation in pure JS). `tr46.toASCII` is byte-identical
 * to Node's `URL.domainToASCII` and to browsers' WHATWG URL IDNA.
 * Using `tr46` instead of `node:url` keeps the library runtime-agnostic
 * (Node, browsers, Deno, Bun, Cloudflare Workers, React Native).
 *
 * @module
 */

import tr46 from "tr46";

/** Cap on the composed `local-part@domain` per §2.3.3 / RFC 5321. */
export const MaxAddressLength = 254;

/** Cap on the local-part per RFC 5321 §4.5.3.1.1. */
export const MaxLocalPartLength = 64;

/** DNS total-length ceiling per RFC 1035. */
export const MaxDomainLength = 253;

/** DNS per-label ceiling per RFC 1035. */
export const MaxDomainLabelLength = 63;

/**
 * Return the local part of `addr` (everything before the final `@`).
 * Returns the entire string if no `@` is present. Operates on raw
 * bytes without validation.
 */
export function addressLocal(addr: string): string {
  const at = addr.lastIndexOf("@");
  if (at < 0) {
    return addr;
  }
  return addr.slice(0, at);
}

/**
 * Return the domain part of `addr` (everything after the final `@`).
 * Returns the empty string if no `@` is present.
 */
export function addressDomain(addr: string): string {
  const at = addr.lastIndexOf("@");
  if (at < 0) {
    return "";
  }
  return addr.slice(at + 1);
}

/**
 * Validate `addr` against the canonical wire form per §2.3:
 *
 *  - Non-empty, valid UTF-8 (always true for JS strings - included
 *    for symmetry with semp-go).
 *  - Composed length ≤ {@link MaxAddressLength} bytes.
 *  - No control characters (C0, DEL, C1).
 *  - Exactly one `@` separator.
 *  - Local-part non-empty, ≤ {@link MaxLocalPartLength} bytes, in
 *    Unicode NFC.
 *  - Domain non-empty, ≤ {@link MaxDomainLength} bytes, ASCII-only,
 *    lowercase, well-formed DNS labels.
 *
 * Throws on the first violation. Pair with {@link canonicalizeAddress}
 * if the input may be denormalized.
 */
export function validateAddress(addr: string): void {
  if (addr === "") {
    throw new Error("brief: empty address");
  }
  const byteLen = utf8ByteLength(addr);
  if (byteLen > MaxAddressLength) {
    throw new Error(`brief: address exceeds ${MaxAddressLength} bytes`);
  }
  rejectControlChars(addr, "address");

  // SplitN(s, "@", 3) semantics: catch zero-or-multiple `@`.
  const firstAt = addr.indexOf("@");
  if (firstAt < 0) {
    throw new Error("brief: address missing '@' separator");
  }
  const lastAt = addr.lastIndexOf("@");
  if (firstAt !== lastAt) {
    throw new Error("brief: address contains multiple '@' separators");
  }

  const local = addr.slice(0, firstAt);
  const domain = addr.slice(firstAt + 1);

  if (local === "") {
    throw new Error("brief: address has empty local part");
  }
  if (utf8ByteLength(local) > MaxLocalPartLength) {
    throw new Error(`brief: local part exceeds ${MaxLocalPartLength} bytes`);
  }
  if (local.normalize("NFC") !== local) {
    throw new Error("brief: local part is not in Unicode Normalization Form C");
  }
  validateDomain(domain);
}

/**
 * Return `addr` in canonical wire form:
 *
 *  - Local-part normalized to Unicode NFC.
 *  - Domain converted to A-label (Punycode) per IDNA2008, folded to
 *    lowercase.
 *
 * Does NOT enforce length or character bounds; pair with
 * {@link validateAddress} on the returned value when ingesting
 * untrusted input.
 */
export function canonicalizeAddress(addr: string): string {
  if (addr === "") {
    throw new Error("brief: empty address");
  }
  const firstAt = addr.indexOf("@");
  if (firstAt < 0) {
    throw new Error("brief: address missing '@' separator");
  }
  const lastAt = addr.lastIndexOf("@");
  if (firstAt !== lastAt) {
    throw new Error("brief: address contains multiple '@' separators");
  }
  const local = addr.slice(0, firstAt).normalize("NFC");
  const domain = addr.slice(firstAt + 1);
  const aLabel = tr46.toASCII(domain, { transitionalProcessing: false }) ?? "";
  if (aLabel === "") {
    throw new Error(`brief: domain ${JSON.stringify(domain)} cannot be converted to A-label`);
  }
  return local + "@" + aLabel.toLowerCase();
}

/**
 * Report whether `a` and `b` denote the same address after
 * canonicalization. Returns false if either side fails
 * canonicalization.
 *
 * Does NOT collapse visually-similar (confusable) characters.
 * Confusables defense is a UI-layer concern per Unicode Technical
 * Standard #39.
 */
export function addressEqual(a: string, b: string): boolean {
  let aa: string;
  let bb: string;
  try {
    aa = canonicalizeAddress(a);
  } catch {
    return false;
  }
  try {
    bb = canonicalizeAddress(b);
  } catch {
    return false;
  }
  return aa === bb;
}

// ---------------------------------------------------------------------------
// Internal helpers

/** Reject any C0 (U+0000-U+001F), DEL (U+007F), or C1 (U+0080-U+009F). */
function rejectControlChars(s: string, field: string): void {
  for (let i = 0; i < s.length; i++) {
    const cp = s.codePointAt(i);
    if (cp === undefined) {
      continue;
    }
    if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      throw new Error(
        `brief: ${field} contains control character U+${cp.toString(16).toUpperCase().padStart(4, "0")} at byte ${i}`,
      );
    }
    if (cp > 0xffff) {
      i++; // step past the surrogate pair's low half
    }
  }
}

function validateDomain(domain: string): void {
  if (domain === "") {
    throw new Error("brief: address has empty domain");
  }
  if (domain.length > MaxDomainLength) {
    throw new Error(`brief: domain exceeds ${MaxDomainLength} bytes`);
  }
  for (let i = 0; i < domain.length; i++) {
    const c = domain.charCodeAt(i);
    if (c > 0x7f) {
      throw new Error(
        "brief: domain contains non-ASCII octet (A-label required on the wire)",
      );
    }
    if (c >= 0x41 && c <= 0x5a) {
      throw new Error(
        "brief: domain contains uppercase letters (must be lowercase on the wire)",
      );
    }
  }
  if (domain.startsWith(".") || domain.endsWith(".")) {
    throw new Error("brief: domain has leading or trailing dot");
  }
  if (domain.includes("..")) {
    throw new Error("brief: domain has empty label (consecutive dots)");
  }
  for (const label of domain.split(".")) {
    if (label === "") {
      throw new Error("brief: domain has empty label");
    }
    if (label.length > MaxDomainLabelLength) {
      throw new Error(
        `brief: domain label ${JSON.stringify(label)} exceeds ${MaxDomainLabelLength} bytes`,
      );
    }
    if (label.startsWith("-") || label.endsWith("-")) {
      throw new Error(
        `brief: domain label ${JSON.stringify(label)} has leading or trailing hyphen`,
      );
    }
    for (const r of label) {
      if (r === "@" || r === " " || r === "\t") {
        throw new Error(
          `brief: domain label ${JSON.stringify(label)} contains disallowed character`,
        );
      }
    }
  }
}

function utf8ByteLength(s: string): number {
  if (typeof Buffer !== "undefined") {
    return Buffer.byteLength(s, "utf8");
  }
  return new TextEncoder().encode(s).length;
}
