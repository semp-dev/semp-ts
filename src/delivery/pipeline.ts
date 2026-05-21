/**
 * Receive-side delivery pipeline per DELIVERY.md §2.
 *
 * Runs the fixed nine-step sequence every envelope passes through
 * before a delivery decision is made:
 *
 *  1. Verify `seal.signature`            -> `seal_invalid`
 *  2. Check `postmark.expires`           -> `envelope_expired`
 *  3. Check `postmark.session_id`        -> `no_session` / `handshake_invalid`
 *  4. Verify `seal.session_mac`          -> `session_mac_invalid`
 *  5. Check domain / server policy       -> `rejected` or `silent`
 *  6. Decrypt `K_brief` from `seal.brief_recipients`
 *  7. Decrypt `envelope.brief`
 *  8. Check user policy (block list)     -> `rejected` or `silent`
 *  9. Deliver to client                  -> `delivered`
 *
 * Each step is a private method so operators can wrap or override
 * individual stages without rewriting orchestration. The exported
 * {@link Pipeline.process} runs all steps in order and short-circuits
 * on the first failure.
 *
 * @module
 */

import { aeadOpen } from "../crypto/index.js";
import {
  type Envelope,
  type RecipientCandidate,
  encodeEnvelope,
  verifySealSignature,
  verifySessionMAC,
} from "../envelope/index.js";
import { type Suite, unwrap as sealUnwrap } from "../seal/index.js";

import type { Acknowledgment, Visibility } from "./ack.js";
import type {
  BlockListLookup,
  BlockListSender,
} from "./blocklist.js";
import { matchBlockList } from "./blocklist.js";
import type { Inbox } from "./inbox.js";
import type { SubmissionResult } from "./submission.js";

/** Minimal logging hook. May be `undefined`. */
export type PipelineLogger = (line: string) => void;

/** Lookup hook returning a domain's published Ed25519 signing key. */
export type DomainKeyLookup = (
  domain: string,
) => Promise<Uint8Array | null>;

/** Hook returning the current `K_env_mac` (to track session rekeys). */
export type EnvMACFunc = () => Uint8Array;

/**
 * Optional pre-block-list per-recipient gate. Returns
 * `{ ack: "delivered" }` to pass the gate; any other ack
 * short-circuits delivery for that recipient.
 */
export type RecipientPolicyFunc = (
  recipient: string,
) =>
  | { ack: "delivered" }
  | { ack: "rejected" | "silent"; reasonCode: string; reason?: string };

/**
 * Optional step-5 hook. Returns `{ ack: "delivered" }` to pass;
 * `rejected` or `silent` terminates the pipeline at this step with
 * an envelope-wide rejection.
 */
export type DomainPolicyFunc = (
  fromDomain: string,
  fromServer: string,
) =>
  | { ack: "delivered" }
  | { ack: "rejected" | "silent"; reasonCode: string; reason?: string };

/** Hook classifying recipient addresses as local vs remote. */
export type LocalAddressFunc = (address: string) => boolean;

/** Optional inbox writer (the bundled {@link Inbox} satisfies this). */
export type InboxStore = Pick<Inbox, "store">;

/** Hook returning the current session-id retired status. */
export type SessionRetiredFunc = (sessionId: string) => Promise<boolean>;

/** Decoded brief shape - minimal fields the pipeline needs. */
export interface DecodedBrief {
  to: string[];
  cc?: string[];
  /** Sender address; surfaced on the brief for visibility / logging. */
  from?: string;
}

/** Inputs to {@link Pipeline}. */
export interface PipelineConfig {
  /** Hook returning K_env_mac for step 4. May be omitted with skipSessionMAC. */
  envMAC?: EnvMACFunc;
  /** Lookup for sender-domain Ed25519 pub for step 1. */
  domainKeys?: DomainKeyLookup;
  /** Optional retired-session lookup for step 3. */
  sessionRetired?: SessionRetiredFunc;
  /** Disable step 1 (used in local-client submission mode). */
  skipSignatureCheck?: boolean;
  /** Disable step 4 (used in local-client submission mode). */
  skipSessionMACCheck?: boolean;
  /** Disable step 2 (testing only). */
  skipExpiryCheck?: boolean;
  /** Disable step 3 (testing only). */
  skipSessionIDCheck?: boolean;
  /**
   * Recipient candidates the home server may use to unwrap
   * `K_brief`. Typically one or more domain encryption keypairs.
   * Required for step 6/7.
   */
  briefRecipients: RecipientCandidate[];
  /** Optional step-5 domain policy. */
  domainPolicy?: DomainPolicyFunc;
  /** Optional pre-block-list per-recipient gate. */
  recipientPolicy?: RecipientPolicyFunc;
  /** Optional step-8 user-level block list lookup. */
  blockList?: BlockListLookup;
  /** Required: classify recipients as local / remote. */
  isLocal: LocalAddressFunc;
  /** Optional inbox writer. Without it, step 9 is a no-op. */
  inbox?: InboxStore;
  /** Optional logger. */
  logger?: PipelineLogger;
  /** Wall-clock hook; defaults to `() => new Date()`. */
  now?: () => Date;
  /** Default clock-skew tolerance for step 2; defaults to 15 minutes. */
  clockSkewMs?: number;
}

/** Envelope-wide rejection produced by steps 1-7. */
export interface PipelineRejection {
  reasonCode: string;
  reason: string;
  silent?: boolean;
}

/** Outcome of a single pipeline run. */
export interface PipelineResult {
  envelopeId: string;
  /** Decoded brief, populated when steps 6/7 succeeded. */
  brief?: DecodedBrief;
  /**
   * Per-recipient outcomes when the pipeline ran past step 7.
   * Empty when {@link rejection} is set.
   */
  results: SubmissionResult[];
  /**
   * Envelope-wide rejection (steps 1-7). Implies {@link results} is
   * empty.
   */
  rejection?: PipelineRejection;
}

/**
 * Receive-side delivery pipeline. Single-process, callable across
 * many envelopes. Concurrency is the caller's responsibility - each
 * `process()` call is independent and stateless beyond the
 * configured hooks.
 */
export class Pipeline {
  private readonly cfg: PipelineConfig;

  constructor(cfg: PipelineConfig) {
    if (cfg.isLocal === undefined) {
      throw new Error("delivery: pipeline missing isLocal classifier");
    }
    if (cfg.briefRecipients.length === 0) {
      throw new Error("delivery: pipeline missing briefRecipients");
    }
    this.cfg = cfg;
  }

  /** Run the full pipeline against `env`. */
  async process(env: Envelope): Promise<PipelineResult> {
    const result: PipelineResult = {
      envelopeId: env.postmark.id,
      results: [],
    };

    // Step 1.
    if (this.cfg.skipSignatureCheck !== true) {
      const rej1 = await this.verifySignature(env);
      if (rej1 !== null) {
        result.rejection = rej1;
        this.log(`step1 reject: ${rej1.reasonCode}`);
        return result;
      }
    }
    // Step 2.
    if (this.cfg.skipExpiryCheck !== true) {
      const rej2 = this.checkExpiry(env);
      if (rej2 !== null) {
        result.rejection = rej2;
        this.log(`step2 reject: ${rej2.reasonCode}`);
        return result;
      }
    }
    // Step 3.
    if (this.cfg.skipSessionIDCheck !== true) {
      const rej3 = await this.checkSessionId(env);
      if (rej3 !== null) {
        result.rejection = rej3;
        this.log(`step3 reject: ${rej3.reasonCode}`);
        return result;
      }
    }
    // Step 4.
    if (this.cfg.skipSessionMACCheck !== true) {
      const rej4 = this.checkSessionMac(env);
      if (rej4 !== null) {
        result.rejection = rej4;
        this.log(`step4 reject: ${rej4.reasonCode}`);
        return result;
      }
    }
    // Step 5.
    const rej5 = this.checkDomainPolicy(env);
    if (rej5 !== null) {
      result.rejection = rej5;
      this.log(`step5 reject: ${rej5.reasonCode}`);
      return result;
    }
    // Steps 6 + 7: home-server brief-only open. We don't need
    // K_enclosure here - only the recipient client does. Walk the
    // configured candidates and try each against
    // env.seal.brief_recipients.
    let brief: DecodedBrief;
    try {
      brief = openBriefOnly(env, this.cfg.briefRecipients) as DecodedBrief;
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      result.rejection = { reasonCode: "seal_invalid", reason };
      this.log(`step6/7 reject: ${reason}`);
      return result;
    }
    if (!Array.isArray(brief.to)) {
      result.rejection = {
        reasonCode: "brief_invalid",
        reason: "brief.to is missing or not an array",
      };
      return result;
    }
    result.brief = brief;

    // Steps 8 + 9.
    const wire = encodeEnvelope(env);
    const recipients = [...brief.to, ...(brief.cc ?? [])];
    for (const recipient of recipients) {
      result.results.push(await this.deliverOne(env, brief, recipient, wire));
    }
    return result;
  }

  // --- Step implementations -----------------------------------------------

  private async verifySignature(
    env: Envelope,
  ): Promise<PipelineRejection | null> {
    if (this.cfg.domainKeys === undefined) {
      return {
        reasonCode: "seal_invalid",
        reason:
          "pipeline missing domainKeys lookup; cannot verify seal.signature",
      };
    }
    const pub = await this.cfg.domainKeys(env.postmark.from_domain);
    if (pub === null || pub.length === 0) {
      return {
        reasonCode: "seal_invalid",
        reason: `no domain key on file for ${env.postmark.from_domain}`,
      };
    }
    let ok = false;
    try {
      ok = verifySealSignature(env, pub);
    } catch (err) {
      return {
        reasonCode: "seal_invalid",
        reason: err instanceof Error ? err.message : String(err),
      };
    }
    if (!ok) {
      return {
        reasonCode: "seal_invalid",
        reason: "seal.signature did not verify",
      };
    }
    return null;
  }

  private checkExpiry(env: Envelope): PipelineRejection | null {
    if (env.postmark.expires === undefined || env.postmark.expires === "") {
      return null;
    }
    const expiryMs = Date.parse(env.postmark.expires);
    if (Number.isNaN(expiryMs)) {
      return {
        reasonCode: "envelope_expired",
        reason: `postmark.expires ${env.postmark.expires} is not ISO 8601`,
      };
    }
    const nowMs = (this.cfg.now ?? (() => new Date()))().getTime();
    const tolerance = this.cfg.clockSkewMs ?? 15 * 60 * 1_000;
    if (nowMs - expiryMs > tolerance) {
      return {
        reasonCode: "envelope_expired",
        reason: `postmark.expires ${env.postmark.expires} is outside the clock-skew tolerance`,
      };
    }
    return null;
  }

  private async checkSessionId(
    env: Envelope,
  ): Promise<PipelineRejection | null> {
    if (env.postmark.session_id.trim() === "") {
      return {
        reasonCode: "no_session",
        reason: "postmark.session_id is empty",
      };
    }
    if (this.cfg.sessionRetired === undefined) {
      return null;
    }
    let retired = false;
    try {
      retired = await this.cfg.sessionRetired(env.postmark.session_id);
    } catch (err) {
      // Lookup failures fail open; log and continue.
      this.log(
        `session retired lookup error for ${env.postmark.session_id}: ${err instanceof Error ? err.message : String(err)}`,
      );
      return null;
    }
    if (retired) {
      return {
        reasonCode: "handshake_invalid",
        reason: `session_id ${env.postmark.session_id} is retired`,
      };
    }
    return null;
  }

  private checkSessionMac(env: Envelope): PipelineRejection | null {
    if (this.cfg.envMAC === undefined) {
      return {
        reasonCode: "session_mac_invalid",
        reason: "pipeline missing envMAC source; cannot verify seal.session_mac",
      };
    }
    const mac = this.cfg.envMAC();
    if (mac.length === 0) {
      return {
        reasonCode: "session_mac_invalid",
        reason: "empty K_env_mac; cannot verify seal.session_mac",
      };
    }
    let ok = false;
    try {
      ok = verifySessionMAC(env, mac);
    } catch (err) {
      return {
        reasonCode: "session_mac_invalid",
        reason: err instanceof Error ? err.message : String(err),
      };
    }
    if (!ok) {
      return {
        reasonCode: "session_mac_invalid",
        reason: "seal.session_mac did not verify",
      };
    }
    return null;
  }

  private checkDomainPolicy(env: Envelope): PipelineRejection | null {
    if (this.cfg.domainPolicy === undefined) {
      return null;
    }
    const verdict = this.cfg.domainPolicy(env.postmark.from_domain, "");
    if (verdict.ack === "delivered") {
      return null;
    }
    return {
      reasonCode: verdict.reasonCode,
      reason: verdict.reason ?? "domain policy rejected envelope",
      silent: verdict.ack === "silent",
    };
  }

  private async deliverOne(
    env: Envelope,
    brief: DecodedBrief,
    recipient: string,
    wire: Uint8Array,
  ): Promise<SubmissionResult> {
    if (!this.cfg.isLocal(recipient)) {
      return {
        recipient,
        status: "rejected",
        reason_code: "recipient_not_found",
        reason: "recipient is not local; caller forwards via federation",
      };
    }
    // Step 8a: optional pre-block-list per-recipient gate.
    if (this.cfg.recipientPolicy !== undefined) {
      const gate = this.cfg.recipientPolicy(recipient);
      if (gate.ack !== "delivered") {
        return {
          recipient,
          status: gate.ack as Acknowledgment,
          reason_code: gate.reasonCode,
          ...(gate.reason !== undefined ? { reason: gate.reason } : {}),
        };
      }
    }
    // Step 8b: user block list.
    if (this.cfg.blockList !== undefined) {
      const sender: BlockListSender =
        brief.from !== undefined
          ? { address: brief.from, domain: brief.from.split("@")[1] ?? "" }
          : { address: "", domain: env.postmark.from_domain };
      const list = await this.cfg.blockList.lookup(recipient);
      const matched = matchBlockList(list, sender);
      if (matched !== null) {
        return {
          recipient,
          status: matched.acknowledgment,
          reason_code: "blocked_recipient",
          ...(matched.reason !== undefined ? { reason: matched.reason } : {}),
        };
      }
    }
    // Step 9: inbox.
    if (this.cfg.inbox !== undefined) {
      this.cfg.inbox.store(recipient, wire);
    }
    return {
      recipient,
      status: "delivered",
    };
  }

  private log(line: string): void {
    if (this.cfg.logger !== undefined) {
      this.cfg.logger(`pipeline ${line}`);
    }
  }
}

/**
 * Home-server brief-only open: walk `candidates`, find the first
 * whose `keyId` is in `env.seal.brief_recipients`, unwrap K_brief
 * with that candidate's X25519 keypair, AEAD-open the brief blob,
 * and return the decoded JSON. Throws if no candidate matches or
 * decryption fails.
 *
 * Distinct from {@link "../envelope".openForRecipient}, which
 * additionally requires the candidate to be an enclosure recipient.
 * The home server only ever receives K_brief, never K_enclosure.
 */
function openBriefOnly(
  env: Envelope,
  candidates: RecipientCandidate[],
): unknown {
  if (candidates.length === 0) {
    throw new Error("envelope: openBriefOnly: empty candidate list");
  }
  // Suite is pinned in seal.algorithm at compose time; the home
  // server unwraps under the same suite. Without this we always
  // use baseline X25519 and reject every PQ envelope at step 6/7.
  const suite = env.seal.algorithm as Suite;
  if (suite !== "x25519-chacha20-poly1305" && suite !== "pq-kyber768-x25519") {
    throw new Error(`envelope: openBriefOnly: unknown seal.algorithm ${suite}`);
  }
  const errors: string[] = [];
  for (const c of candidates) {
    const wrapped = env.seal.brief_recipients[c.keyId];
    if (typeof wrapped !== "string") {
      continue;
    }
    try {
      const kBrief = sealUnwrap(
        suite,
        c.privateKey,
        c.publicKey,
        wrapped,
      );
      const briefBlob = base64Decode(env.brief);
      if (briefBlob.length < 12) {
        throw new Error("brief blob too short");
      }
      const briefNonce = briefBlob.slice(0, 12);
      const briefCT = briefBlob.slice(12);
      const aad = new TextEncoder().encode(env.postmark.id);
      const briefPT = aeadOpen(
        "chacha20-poly1305",
        kBrief,
        briefNonce,
        briefCT,
        aad,
      );
      return JSON.parse(new TextDecoder().decode(briefPT));
    } catch (err) {
      errors.push(
        `${c.keyId}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  if (errors.length === 0) {
    throw new Error(
      "envelope: openBriefOnly: no candidate matches a brief recipient slot",
    );
  }
  throw new Error(
    `envelope: openBriefOnly: every candidate failed: ${errors.join("; ")}`,
  );
}

function base64Decode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

// Surface unused Visibility import for downstream consumers. Visibility is the
// per-recipient status-visibility config used by ack.ts; the pipeline doesn't
// gate on it directly, but exporting it from the index is convenient.
export type { Visibility };
