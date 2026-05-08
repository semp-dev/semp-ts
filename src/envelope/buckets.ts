/**
 * Envelope size and recipient-count bucket math per ENVELOPE.md
 * §2.4.1 (size) and §4.4.2 (recipient count).
 *
 * @module
 */

/**
 * Smallest envelope size bucket (the protocol floor). Every
 * envelope, including the smallest plaintext-only message, occupies
 * at least 4 KB on the wire.
 */
export const MinEnvelopeSizeBucket = 4096;

/**
 * Default ceiling on envelope size. A deployment may configure a
 * smaller `max_envelope_size` via the negotiated session limit; this
 * is the protocol-default fallback.
 */
export const DefaultMaxEnvelopeSize = 25 * 1024 * 1024;

/**
 * Select the size bucket for an unpadded envelope of the given byte
 * size per the default power-of-two curve (4096, 8192, 16384, ...).
 *
 * Throws on negative input or input that exceeds the ceiling — over-
 * limit envelopes MUST be recomposed; padding is not a remedy for
 * over-limit content.
 */
export function selectSizeBucket(
  unpaddedSize: number,
  maxEnvelopeSize?: number,
): number {
  if (!Number.isInteger(unpaddedSize) || unpaddedSize < 0) {
    throw new Error(`envelope: invalid unpadded size ${unpaddedSize}`);
  }
  const ceiling = maxEnvelopeSize ?? DefaultMaxEnvelopeSize;
  if (ceiling <= 0) {
    throw new Error(`envelope: non-positive ceiling ${ceiling}`);
  }
  if (unpaddedSize > ceiling) {
    throw new Error(
      `envelope: unpadded size ${unpaddedSize} exceeds max_envelope_size ${ceiling}`,
    );
  }
  let bucket = MinEnvelopeSizeBucket;
  while (bucket < unpaddedSize) {
    const next = bucket * 2;
    if (next > ceiling) {
      return ceiling;
    }
    bucket = next;
  }
  return bucket;
}

/**
 * Select the recipient-count bucket per §4.4.2. The floor is 2
 * unless `realRecipients === 1` AND `singleDomainNotGroup` is true,
 * in which case the floor relaxes to 1 (a single-domain non-group
 * send reveals only the obvious cardinality and gains no
 * obfuscation from padding to 2). Real counts above 1024 force
 * recomposition into multiple envelopes — the runner returns a
 * sentinel of -1 in that case so callers can detect it.
 */
export function selectRecipientCountBucket(
  realRecipients: number,
  singleDomainNotGroup: boolean,
): number {
  if (!Number.isInteger(realRecipients) || realRecipients < 0) {
    throw new Error(`envelope: invalid recipient count ${realRecipients}`);
  }
  if (realRecipients === 1 && singleDomainNotGroup) {
    return 1;
  }
  if (realRecipients > 1024) {
    return -1; // recomposition required
  }
  let bucket = 2;
  while (bucket < realRecipients) {
    bucket *= 2;
  }
  return bucket;
}
