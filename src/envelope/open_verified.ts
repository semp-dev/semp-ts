/**
 * Open + verify orchestrator per ENVELOPE.md §6 + §7.2.
 *
 * `openAndVerify` runs the full receipt-side check on an envelope
 * delivered to a recipient client:
 *
 *   1. Resolve the sender domain's signing public key via the
 *      caller-supplied {@link SenderKeyResolver}.
 *   2. Verify `seal.signature` against that key.
 *   3. Walk the supplied recipient candidates and open the brief +
 *      enclosure for the first matching device key.
 *
 * `openAndVerify` does NOT run `seal.session_mac` — that is the
 * routing-server / receiving-server check between adjacent SEMP
 * peers; the recipient client uses {@link "./verify".verifySessionMAC}
 * separately when it has access to the K_env_mac.
 *
 * @module
 */

import {
  type Envelope,
  type OpenInput,
} from "./compose.js";
import {
  type OpenedBrief,
  type OpenedEnclosure,
  type RecipientCandidate,
  openBriefAny,
  openEnclosureAny,
} from "./open_any.js";
import { verifySealSignature } from "./verify.js";

/**
 * Caller-supplied lookup for the sender domain's signing public
 * key. Returns the 32-byte Ed25519 public key for the domain that
 * originated `env.postmark.from_domain`, or null/throws when the
 * key cannot be resolved.
 */
export interface SenderKeyResolver {
  lookupSenderDomainPub(
    fromDomain: string,
    keyId: string,
  ): Promise<Uint8Array | null>;
}

/** Functional shorthand for {@link SenderKeyResolver}. */
export type SenderKeyResolverFunc = (
  fromDomain: string,
  keyId: string,
) => Promise<Uint8Array | null>;

/** Inputs to {@link openAndVerify}. */
export interface OpenAndVerifyInput {
  suite: OpenInput["suite"];
  envelope: Envelope;
  candidates: RecipientCandidate[];
  /** Either a {@link SenderKeyResolver} or its functional form. */
  resolver: SenderKeyResolver | SenderKeyResolverFunc;
}

/** Result of a successful {@link openAndVerify}. */
export interface OpenAndVerifyResult {
  /** Sender domain public key the signature verified under. */
  senderDomainPub: Uint8Array;
  /** Recipient candidate that successfully opened the slots. */
  candidate: RecipientCandidate;
  /** Decoded brief plaintext. */
  brief: unknown;
  /** Decoded enclosure plaintext. */
  enclosure: unknown;
}

/**
 * Run sender-signature verification + multi-candidate open. Returns
 * the opened plaintexts plus the matched candidate and the resolved
 * sender public key. Throws on missing sender key, signature
 * mismatch, or open failure.
 */
export async function openAndVerify(
  input: OpenAndVerifyInput,
): Promise<OpenAndVerifyResult> {
  const env = input.envelope;
  const fromDomain = env.postmark.from_domain;
  const keyId = env.seal.key_id;
  const lookup = isResolver(input.resolver)
    ? input.resolver.lookupSenderDomainPub.bind(input.resolver)
    : input.resolver;

  const pub = await lookup(fromDomain, keyId);
  if (pub === null) {
    throw new Error(
      `envelope: openAndVerify: resolver returned null for sender domain ${JSON.stringify(fromDomain)}, key_id ${JSON.stringify(keyId)}`,
    );
  }
  if (!verifySealSignature(env, pub)) {
    throw new Error(
      "envelope: openAndVerify: seal.signature did not verify under the resolved sender domain key",
    );
  }

  let brief: OpenedBrief;
  let enclosure: OpenedEnclosure;
  try {
    brief = openBriefAny(input.suite, env, input.candidates);
  } catch (err) {
    throw new Error(
      `envelope: openAndVerify: open brief failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  try {
    enclosure = openEnclosureAny(input.suite, env, input.candidates);
  } catch (err) {
    throw new Error(
      `envelope: openAndVerify: open enclosure failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return {
    senderDomainPub: pub,
    candidate: brief.candidate,
    brief: brief.brief,
    enclosure: enclosure.enclosure,
  };
}

function isResolver(
  r: SenderKeyResolver | SenderKeyResolverFunc,
): r is SenderKeyResolver {
  return (
    typeof (r as SenderKeyResolver).lookupSenderDomainPub === "function"
  );
}
