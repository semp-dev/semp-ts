/**
 * Typed envelope-rejection error per ENVELOPE.md §9.
 *
 * The verify / open primitives surface structural and cryptographic
 * failures as plain `Error` instances; consumers that need to map
 * these onto the protocol's rejection reason codes can wrap or
 * re-throw them as {@link EnvelopeRejection}.
 *
 * @module
 */

import type { ReasonCode } from "../reasoncodes.js";

/** Error subtype carrying a SEMP rejection reason code. */
export class EnvelopeRejection extends Error {
  override readonly name = "EnvelopeRejection";
  readonly reasonCode: ReasonCode;
  /** Optional operator-supplied human-readable description. */
  readonly reasonText: string | undefined;

  constructor(reasonCode: ReasonCode, reasonText?: string, message?: string) {
    super(
      message ??
        (reasonText !== undefined && reasonText !== ""
          ? `envelope rejected: ${reasonCode} (${reasonText})`
          : `envelope rejected: ${reasonCode}`),
    );
    this.reasonCode = reasonCode;
    this.reasonText = reasonText;
  }
}

/** Type guard for {@link EnvelopeRejection}. */
export function isEnvelopeRejection(err: unknown): err is EnvelopeRejection {
  return err instanceof EnvelopeRejection;
}
