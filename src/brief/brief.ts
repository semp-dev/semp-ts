/**
 * The decrypted form of `envelope.brief` per ENVELOPE.md §5.1.
 *
 * The brief is encrypted in transit under K_brief; this module
 * provides the typed shape of the JSON payload after decryption,
 * plus the {@link splitForBCC} helper that materializes BCC
 * recipients into per-recipient envelope copies (CLIENT.md §3.5,
 * ENVELOPE.md §5.3).
 *
 * @module
 */

/** Decrypted brief payload. */
export interface Brief {
  /**
   * Globally unique message identifier. Distinct from
   * `postmark.id`, which is a per-transaction routing id.
   */
  message_id: string;

  /** Full sender address (canonical form per §2.3). */
  from: string;

  /** Primary recipient addresses. */
  to: string[];

  /** Optional carbon copy recipients. */
  cc?: string[];

  /**
   * For an envelope copy delivered to a specific BCC recipient,
   * contains only that recipient's address. MUST be absent from
   * envelope copies delivered to to/cc recipients.
   */
  bcc?: string[];

  /** Optional address that replies should target instead of `from`. */
  reply_to?: string;

  /** Wall-clock time of message creation at the sender, ISO 8601 UTC. */
  sent_at: string;

  /** Stable identifier of the conversation thread. */
  thread_id?: string;

  /** Group / mailing-list identifier. */
  group_id?: string;

  /** `message_id` of the message being replied to. */
  in_reply_to?: string;

  /**
   * Recipient-server-and-client-visible private metadata extensions.
   */
  extensions?: Record<string, unknown>;
}

/**
 * Materialize a {@link Brief} with BCC recipients into the set of
 * per-recipient copies required by CLIENT.md §3.5 and ENVELOPE.md
 * §5.3.
 *
 * SEMP's privacy model forbids server-side BCC stripping: a sending
 * client MUST generate one distinct envelope copy per BCC recipient
 * so that the `bcc` field contains only that recipient's address in
 * each copy, and is absent entirely from the copy delivered to
 * to/cc recipients. The sending server never sees the full BCC
 * list.
 *
 * Returned copies:
 *
 *  1. If `b.bcc` is empty or undefined, returns `[b]` — a single
 *     copy, returned unchanged.
 *
 *  2. Otherwise, returns `b.bcc.length + 1` elements:
 *     - One "visible" copy for to + cc recipients, with `bcc`
 *       removed entirely.
 *     - One copy per original BCC recipient, each carrying that
 *       single address in `bcc`. All other fields are preserved so
 *       each recipient sees the same primary recipient list.
 *
 * The returned briefs share the underlying `extensions` map and
 * address arrays with the input by reference. Callers that mutate
 * a copy independently should clone first.
 */
export function splitForBCC(b: Brief): Brief[] {
  if (b.bcc === undefined || b.bcc.length === 0) {
    return [b];
  }
  const out: Brief[] = [];

  // Copy 0: visible to/cc recipients. The `bcc` field is removed so
  // the canonical JSON does not include it.
  const visible: Brief = { ...b };
  delete visible.bcc;
  out.push(visible);

  // Copies 1..N: one per BCC recipient.
  for (const recipient of b.bcc) {
    out.push({ ...b, bcc: [recipient] });
  }

  return out;
}
