/**
 * Multi-recipient open helpers per ENVELOPE.md §6.
 *
 * A recipient client may hold multiple device keys (KEY.md §10).
 * `openBriefAny` and `openEnclosureAny` walk a list of candidate
 * recipient private keys, attempt to unwrap each in turn, and return
 * the result from the first matching slot.
 *
 * @module
 */

import {
  type Envelope,
  type OpenInput,
  openForRecipient,
} from "./compose.js";

/** One candidate recipient identity to try when opening. */
export interface RecipientCandidate {
  /** Recipient client key id (matches a key in seal.*_recipients). */
  keyId: string;
  /** 32-byte X25519 (or 2432-byte hybrid) private key. */
  privateKey: Uint8Array;
  /** 32-byte X25519 (or 1216-byte hybrid) public key. */
  publicKey: Uint8Array;
}

/** Result of a successful multi-recipient brief open. */
export interface OpenedBrief {
  /** The candidate that successfully unwrapped K_brief. */
  candidate: RecipientCandidate;
  /** Decoded brief plaintext (parsed from canonical JSON). */
  brief: unknown;
}

/** Result of a successful multi-recipient enclosure open. */
export interface OpenedEnclosure {
  /** The candidate that successfully unwrapped K_enclosure. */
  candidate: RecipientCandidate;
  /** Decoded enclosure plaintext (parsed from canonical JSON). */
  enclosure: unknown;
}

/**
 * Walk `candidates` and try each recipient identity against
 * `env.seal.brief_recipients`. Returns the brief plaintext from the
 * first matching slot whose AEAD tag verifies. Throws when no
 * candidate matches a slot or every candidate's AEAD open fails.
 */
export function openBriefAny(
  suite: OpenInput["suite"],
  env: Envelope,
  candidates: RecipientCandidate[],
): OpenedBrief {
  if (candidates.length === 0) {
    throw new Error("envelope: openBriefAny: empty candidate list");
  }
  const errors: string[] = [];
  for (const c of candidates) {
    if (env.seal.brief_recipients[c.keyId] === undefined) {
      continue; // not a brief recipient
    }
    try {
      const opened = openForRecipient({
        suite,
        envelope: env,
        recipientKeyId: c.keyId,
        recipientPrivateKey: c.privateKey,
        recipientPublicKey: c.publicKey,
      });
      return { candidate: c, brief: opened.brief };
    } catch (err) {
      errors.push(
        `${c.keyId}: ${err instanceof Error ? err.message : String(err)}`,
      );
      continue;
    }
  }
  if (errors.length === 0) {
    throw new Error(
      "envelope: openBriefAny: no candidate matches a brief recipient slot",
    );
  }
  throw new Error(
    `envelope: openBriefAny: every candidate failed: ${errors.join("; ")}`,
  );
}

/**
 * Walk `candidates` and try each against
 * `env.seal.enclosure_recipients`. Returns the enclosure plaintext
 * from the first matching slot whose AEAD tag verifies.
 */
export function openEnclosureAny(
  suite: OpenInput["suite"],
  env: Envelope,
  candidates: RecipientCandidate[],
): OpenedEnclosure {
  if (candidates.length === 0) {
    throw new Error("envelope: openEnclosureAny: empty candidate list");
  }
  const errors: string[] = [];
  for (const c of candidates) {
    if (env.seal.enclosure_recipients[c.keyId] === undefined) {
      continue; // not an enclosure recipient
    }
    try {
      const opened = openForRecipient({
        suite,
        envelope: env,
        recipientKeyId: c.keyId,
        recipientPrivateKey: c.privateKey,
        recipientPublicKey: c.publicKey,
      });
      return { candidate: c, enclosure: opened.enclosure };
    } catch (err) {
      errors.push(
        `${c.keyId}: ${err instanceof Error ? err.message : String(err)}`,
      );
      continue;
    }
  }
  if (errors.length === 0) {
    throw new Error(
      "envelope: openEnclosureAny: no candidate matches an enclosure recipient slot",
    );
  }
  throw new Error(
    `envelope: openEnclosureAny: every candidate failed: ${errors.join("; ")}`,
  );
}
