/**
 * Discovery layer per DISCOVERY.md.
 *
 * Today: DNS TXT capability parsing (§2.2), well-known URI
 * configuration + domain-keys fetch (§3), and a high-level
 * {@link resolveServer} that yields the `serverDomainPub` a
 * `runClient` call needs. Future: DNS SRV resolution,
 * configuration-update verification, lookup (§4), caching (§6).
 *
 * @module
 */

export { parseTXTCapabilities, type TXTCapabilities } from "./txt.js";

export {
  type ConfigEndpoints,
  type ConfigExtension,
  type ConfigLimits,
  type Configuration,
  type TransportEndpoints,
  ConfigurationType,
  WellKnownMaxBytes,
  WellKnownPath,
  parseConfiguration,
} from "./configuration.js";

export {
  type DomainKeys,
  type KeyBlock,
  DomainKeysMaxBytes,
  DomainKeysType,
  decodeKeyBlockPublic,
  parseDomainKeys,
  verifyDomainKeyFingerprint,
} from "./domain_keys.js";

export {
  type FetchLike,
  type FetchOptions,
  type ResolveServerOptions,
  type ResolvedServer,
  fetchConfiguration,
  fetchDomainKeys,
  resolveServer,
  wellKnownUrl,
} from "./resolver.js";
