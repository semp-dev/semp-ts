/**
 * SEMP upgrade-signaling SMTP headers per
 * draft-gokce-semp-client §5.7.
 *
 * A SEMP-capable client SHOULD include these on every outbound
 * SMTP message so a receiving SEMP-capable client can offer a
 * thread upgrade without an additional DNS lookup. A recipient
 * client that acts on the signal MUST verify the advertised
 * identity by completing SEMP discovery against
 * {@link UpgradeHeaderDomain} and fetching the identity key from
 * that domain before treating the upgrade as trusted.
 *
 * The signal is unauthenticated at the SMTP layer; treat the
 * headers as a hint only.
 *
 * @module
 */

/**
 * Boolean-style header name set to {@link UpgradeCapabilityPresent}
 * whenever the sender's client can receive via SEMP at a published
 * SEMP address.
 */
export const UpgradeHeaderCapability = "SEMP-Capability";

/**
 * Header carrying the fingerprint of the sender's current SEMP
 * identity public key in `<algorithm>:<hex>` form (for example
 * `ed25519:abc123...`).
 */
export const UpgradeHeaderIdentity = "SEMP-Identity";

/**
 * Header naming the sender's SEMP domain (the domain part of the
 * sender's SEMP address). MAY differ from the domain of the SMTP
 * `From` header.
 */
export const UpgradeHeaderDomain = "SEMP-Domain";

/**
 * Header carrying the full SEMP address of the sender so the
 * recipient does not have to infer it from the SMTP `From`
 * local-part when the SMTP and SEMP local-parts differ.
 */
export const UpgradeHeaderAddress = "SEMP-Address";

/**
 * Value the sender writes into the {@link UpgradeHeaderCapability}
 * header. Single fixed value; future spec versions may extend the
 * vocabulary.
 */
export const UpgradeCapabilityPresent = "1";
