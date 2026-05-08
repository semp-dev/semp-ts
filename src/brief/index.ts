/**
 * Brief layer per ENVELOPE.md §2.3 + §5.1 + §5.3.
 *
 * Address canonicalization, validation, equality, and the typed
 * brief payload shape with the BCC fan-out helper.
 *
 * @module
 */

export {
  MaxAddressLength,
  MaxDomainLabelLength,
  MaxDomainLength,
  MaxLocalPartLength,
  addressDomain,
  addressEqual,
  addressLocal,
  canonicalizeAddress,
  validateAddress,
} from "./address.js";

export { type Brief, splitForBCC } from "./brief.js";
