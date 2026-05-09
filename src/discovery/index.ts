/**
 * Discovery layer per DISCOVERY.md.
 *
 * DNS lookups (SRV / TXT / MX), well-known URI configuration +
 * domain-keys fetch (§3), signed SEMP_DISCOVERY lookup (§4), and
 * a discovery result cache (§6.1).
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

export {
  type DNSLookup,
  type MXRecord,
  type SRVRecord,
  defaultDNSLookup,
  lookupMX,
  lookupSRV,
  lookupTXT,
} from "./dns.js";

export {
  type DiscoveryCache,
  DefaultTTLLegacyMs,
  DefaultTTLNotFoundMs,
  DefaultTTLSEMPMs,
  InMemoryDiscoveryCache,
} from "./cache.js";

export {
  type DiscoveryRequest,
  type DiscoveryResponse,
  type DiscoveryResult,
  type DiscoverySignature,
  type DiscoveryStatus,
  DiscoveryMessageType,
  DiscoveryRecordVersion,
  DiscoverySignaturePrefix,
  DiscoveryStepRequest,
  DiscoveryStepResponse,
  signDiscoveryResponse,
  validateDiscoveryRequest,
  validateDiscoveryResponse,
  verifyDiscoveryResponse,
} from "./lookup.js";

export {
  OnionSuffix,
  OnionV3LabelLength,
  isOnionDomain,
  validateOnionDomain,
} from "./onion.js";

export {
  type AlphaRange,
  type PartitionConfig,
  type PartitionLookupFunc,
  type PartitionResolverConfig,
  type PartitionStrategy,
  defaultAlphaRanges,
  parsePartitionTXT,
  resolvePartition,
} from "./partition.js";
