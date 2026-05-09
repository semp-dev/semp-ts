/**
 * Envelope compose / open per ENVELOPE.md §4 + §6.5 + §7.1 + §7.2.
 *
 * The envelope is the wire object that carries one SEMP message
 * between servers. Compose builds it; open recovers the brief and
 * enclosure from a received envelope.
 *
 * This module exposes both the production path (fresh randomness)
 * and the deterministic path (caller-pinned randomness for vectors
 * + audits). The deterministic path is what the cross-language
 * vectors-runner exercises; production callers MUST use the
 * fresh-randomness form.
 *
 * Layered on top of:
 *   - canonical/marshal      §4.3 canonical bytes (and elision)
 *   - seal/wrap              §4.4.1 per-recipient key wrap
 *   - crypto/aead            §7.1.1 brief / enclosure AEAD
 *   - keys/sign              §6.5 sender_signature
 *   - HMAC-SHA-256           §4.3 session_mac
 *
 * @module
 */

import {
  type AEADAlgorithm,
  aeadOpen,
  aeadSeal,
  computeMAC,
} from "../crypto/index.js";
import {
  marshal as canonicalMarshal,
  marshalWithElision,
} from "../canonical/index.js";
import { sign as ed25519Sign } from "../keys/index.js";
import {
  type Suite,
  type WrapRandomness,
  unwrap as sealUnwrap,
  wrapWithRandomness,
} from "../seal/index.js";

/** Algorithm prefix for the seal signature, per ENVELOPE.md §4.3. */
const EnvelopePrefix = "SEMP-ENVELOPE:";

/**
 * Postmark fields populated at compose time. `hop_count` is set by
 * relays in transit and is excluded from canonical bytes; it's
 * not on the compose surface.
 */
export interface PostmarkFields {
  id: string;
  session_id: string;
  from_domain: string;
  to_domain: string;
  /** ISO 8601 timestamp string. */
  expires: string;
  extensions?: Record<string, unknown>;
}

/** One recipient slot in the seal. */
export interface RecipientKey {
  /** SEMP fingerprint (lowercase hex of SHA-256(public_key)). */
  keyId: string;
  /** Recipient public key bytes (X25519 32B or hybrid 1216B per suite). */
  publicKey: Uint8Array;
}

/**
 * Inputs to envelope compose. All fields are required so the result
 * is byte-deterministic given the inputs.
 */
export interface ComposeInput {
  /** Algorithm suite. */
  suite: Suite;
  /** Sender domain signing key id (lowercase-hex SHA-256 fingerprint). */
  sealKeyId: string;
  /** 32-byte Ed25519 secret seed for the sender domain signing key. */
  senderDomainSigningSeed: Uint8Array;
  /** Postmark fields. */
  postmark: PostmarkFields;
  /** Brief payload (will be canonicalized, then AEAD-sealed). */
  briefPlaintext: unknown;
  /** Enclosure payload (already-signed enclosure; will be canonicalized + AEAD-sealed). */
  enclosurePlaintext: unknown;
  /** Per-recipient keys for the brief slot (server + clients). */
  briefRecipients: RecipientKey[];
  /** Per-recipient keys for the enclosure slot (clients only). */
  enclosureRecipients: RecipientKey[];
  /** 32-byte symmetric key wrapped to every brief recipient. */
  kBrief: Uint8Array;
  /** 32-byte symmetric key wrapped to every enclosure recipient. */
  kEnclosure: Uint8Array;
  /** Envelope MAC key derived from the session. */
  kEnvMAC: Uint8Array;
  /** AEAD nonce for the brief seal call (12 bytes for both suites). */
  briefAEADNonce: Uint8Array;
  /** AEAD nonce for the enclosure seal call (12 bytes for both suites). */
  enclosureAEADNonce: Uint8Array;
  /**
   * Per-recipient wrap randomness. Keyed by keyId. Each entry must
   * carry the X25519 ephemeral private key; the PQ suite also
   * requires kyberEncapsRandomnessM. The runner pins these per
   * vector; production callers either generate them fresh or
   * forward them from a higher layer.
   */
  wrapRandomness: ReadonlyMap<string, WrapRandomness>;
  /** Top-level extensions object (default: {}). */
  extensions?: Record<string, unknown>;
  /** Seal-layer extensions (default: {}). */
  sealExtensions?: Record<string, unknown>;
}

/** Wire envelope returned by {@link compose}. */
export interface Envelope {
  type: "SEMP_ENVELOPE";
  version: "1.0.0";
  postmark: PostmarkFields;
  seal: {
    algorithm: string;
    key_id: string;
    signature: string;
    session_mac: string;
    brief_recipients: Record<string, string>;
    enclosure_recipients: Record<string, string>;
    extensions?: Record<string, unknown>;
  };
  brief: string;
  enclosure: string;
  /** Optional opaque base64-alphabet filler for size-bucket padding (§2.4). */
  padding?: string;
  extensions?: Record<string, unknown>;
}

/** AEAD algorithm tied to the suite for brief/enclosure encryption. */
function suiteBriefEnclosureAEAD(suite: Suite): AEADAlgorithm {
  // Both currently defined suites use ChaCha20-Poly1305 for brief
  // and enclosure (12-byte nonce per §7.1.1). Only the KEM is PQ.
  void suite;
  return "chacha20-poly1305";
}

/**
 * Compose a wire envelope. Deterministic given the inputs (every
 * randomness source is caller-supplied). Returns the wire envelope
 * with seal.signature and seal.session_mac populated.
 *
 * Compose order:
 *
 *   1. AEAD-Seal the brief (canonical) under K_brief with the
 *      brief AEAD nonce and postmark.id as AAD per §7.1.1.
 *      `envelope.brief = base64(nonce || aead_ct)`.
 *   2. AEAD-Seal the enclosure same way under K_enclosure.
 *   3. Wrap K_brief to every brief recipient.
 *   4. Wrap K_enclosure to every enclosure recipient.
 *   5. Build the envelope object with seal.signature = "" and
 *      seal.session_mac = "" placeholders.
 *   6. Compute canonical bytes per §4.3 (signature + mac blanked,
 *      hop_count and padding omitted), prepend SEMP-ENVELOPE:,
 *      Ed25519-sign with the sender domain signing seed.
 *   7. Compute HMAC-SHA-256 over the same canonical bytes with
 *      K_env_mac.
 *   8. Write both back into the envelope.
 */
export function compose(input: ComposeInput): Envelope {
  const aead = suiteBriefEnclosureAEAD(input.suite);
  const postmarkID = new TextEncoder().encode(input.postmark.id);

  // Step 1: brief AEAD.
  const briefCanonical = canonicalMarshal(input.briefPlaintext);
  const briefCT = aeadSeal(
    aead,
    input.kBrief,
    input.briefAEADNonce,
    briefCanonical,
    postmarkID,
  );
  const briefField = base64Encode(concat(input.briefAEADNonce, briefCT));

  // Step 2: enclosure AEAD.
  const enclosureCanonical = canonicalMarshal(input.enclosurePlaintext);
  const enclosureCT = aeadSeal(
    aead,
    input.kEnclosure,
    input.enclosureAEADNonce,
    enclosureCanonical,
    postmarkID,
  );
  const enclosureField = base64Encode(concat(input.enclosureAEADNonce, enclosureCT));

  // Step 3: wrap K_brief per recipient.
  const briefRecipients: Record<string, string> = {};
  for (const r of input.briefRecipients) {
    const rand = input.wrapRandomness.get(r.keyId);
    if (rand === undefined) {
      throw new Error(`compose: missing wrap randomness for brief recipient ${r.keyId}`);
    }
    briefRecipients[r.keyId] = wrapWithRandomness(input.suite, r.publicKey, input.kBrief, rand);
  }

  // Step 4: wrap K_enclosure per recipient.
  const enclosureRecipients: Record<string, string> = {};
  for (const r of input.enclosureRecipients) {
    const rand = input.wrapRandomness.get(`enclosure:${r.keyId}`)
      ?? input.wrapRandomness.get(r.keyId);
    if (rand === undefined) {
      throw new Error(
        `compose: missing wrap randomness for enclosure recipient ${r.keyId}`,
      );
    }
    enclosureRecipients[r.keyId] = wrapWithRandomness(
      input.suite,
      r.publicKey,
      input.kEnclosure,
      rand,
    );
  }

  // Step 5: assemble with placeholder signature + MAC.
  //
  // Wire-shape rules:
  //   postmark.extensions and seal.extensions DEFAULT to {} when
  //     the caller doesn't pass them — these slots are always
  //     present on the wire (some routers depend on the keys
  //     existing as a marker even when empty).
  //   Top-level extensions DEFAULTS to absent — the spec treats
  //     it as truly optional.
  const postmark: PostmarkFields = {
    ...input.postmark,
    extensions: input.postmark.extensions ?? {},
  };

  const seal: Envelope["seal"] = {
    algorithm: input.suite,
    key_id: input.sealKeyId,
    signature: "",
    session_mac: "",
    brief_recipients: briefRecipients,
    enclosure_recipients: enclosureRecipients,
    extensions: input.sealExtensions ?? {},
  };

  const env: Envelope = {
    type: "SEMP_ENVELOPE",
    version: "1.0.0",
    postmark,
    seal,
    brief: briefField,
    enclosure: enclosureField,
  } as Envelope;
  if (input.extensions !== undefined) {
    env.extensions = input.extensions;
  }

  // Step 6: §4.3 canonical bytes and seal.signature.
  const canonical = canonicalEnvelopeFor(env);
  const signingInput = concat(new TextEncoder().encode(EnvelopePrefix), canonical);
  const sig = ed25519Sign(input.senderDomainSigningSeed, signingInput);
  env.seal.signature = base64Encode(sig);

  // Step 7: session MAC over the SAME canonical bytes (signature
  // and session_mac were both blanked, so both proofs cover the
  // same input).
  const mac = computeMAC(input.kEnvMAC, canonical);
  env.seal.session_mac = base64Encode(mac);

  return env;
}

/**
 * Compute the §4.3 canonical envelope bytes — signature and
 * session_mac blanked, hop_count and padding omitted.
 */
export function canonicalEnvelopeFor(envelope: unknown): Uint8Array {
  return marshalWithElision(envelope, (clone) => {
    if (!isRecord(clone)) {
      return;
    }
    delete clone.padding;
    const seal = clone.seal;
    if (isRecord(seal)) {
      if ("signature" in seal) {
        seal.signature = "";
      }
      if ("session_mac" in seal) {
        seal.session_mac = "";
      }
    }
    const postmark = clone.postmark;
    if (isRecord(postmark)) {
      delete postmark.hop_count;
    }
  });
}

/**
 * Inputs to {@link openForRecipient}. Targets one recipient client;
 * for the multi-recipient case the caller iterates over the slot
 * map and tries each client priv until one succeeds.
 */
export interface OpenInput {
  suite: Suite;
  envelope: Envelope;
  /** Recipient client key id (matches a key in seal.*_recipients). */
  recipientKeyId: string;
  /** Recipient client private key (32B X25519 or 2432B hybrid). */
  recipientPrivateKey: Uint8Array;
  /** Recipient client public key (32B X25519 or 1216B hybrid). */
  recipientPublicKey: Uint8Array;
}

/** Output of a successful open: recovered brief + enclosure plaintexts. */
export interface OpenedEnvelope {
  /** Decoded brief (parsed from canonical JSON). */
  brief: unknown;
  /** Decoded enclosure (parsed from canonical JSON). */
  enclosure: unknown;
}

/**
 * Open an envelope for a specific recipient. Inverts {@link compose}:
 * unwraps K_brief and K_enclosure, AEAD-decrypts both fields, and
 * returns the parsed plaintexts. Throws if the recipient slot is
 * absent or the AEAD tag does not verify.
 *
 * Does NOT verify seal.signature or seal.session_mac — those are
 * the routing-server / receiving-server checks per §7.2 and live
 * on the server side. {@link verifySealSignature} and
 * {@link verifySessionMAC} are the corresponding verifier helpers.
 */
export function openForRecipient(input: OpenInput): OpenedEnvelope {
  const brief = openBriefForRecipient(input);
  const enclosure = openEnclosureForRecipient(input);
  return { brief, enclosure };
}

/**
 * Open just the brief slot for a specific recipient. Servers (which
 * sit in `brief_recipients` for routing but NOT in `enclosure_recipients`)
 * use this; clients that hold both slots use {@link openForRecipient}.
 *
 * Throws if the recipient is absent from `brief_recipients` or the
 * AEAD tag does not verify.
 */
export function openBriefForRecipient(input: OpenInput): unknown {
  const aead = suiteBriefEnclosureAEAD(input.suite);
  const env = input.envelope;
  const postmarkID = new TextEncoder().encode(env.postmark.id);

  const briefWrapped = env.seal.brief_recipients[input.recipientKeyId];
  if (typeof briefWrapped !== "string") {
    throw new Error(
      `open: recipient ${input.recipientKeyId} not in brief_recipients`,
    );
  }
  const kBrief = sealUnwrap(
    input.suite,
    input.recipientPrivateKey,
    input.recipientPublicKey,
    briefWrapped,
  );

  const briefBlob = base64Decode(env.brief);
  if (briefBlob.length < 12) {
    throw new Error("open: brief blob too short");
  }
  const briefNonce = briefBlob.slice(0, 12);
  const briefCT = briefBlob.slice(12);
  const briefPT = aeadOpen(aead, kBrief, briefNonce, briefCT, postmarkID);
  return JSON.parse(new TextDecoder().decode(briefPT));
}

/**
 * Open just the enclosure slot for a specific recipient. Mirror of
 * {@link openBriefForRecipient}. Throws if the recipient is absent
 * from `enclosure_recipients` or the AEAD tag does not verify.
 */
export function openEnclosureForRecipient(input: OpenInput): unknown {
  const aead = suiteBriefEnclosureAEAD(input.suite);
  const env = input.envelope;
  const postmarkID = new TextEncoder().encode(env.postmark.id);

  const enclosureWrapped = env.seal.enclosure_recipients[input.recipientKeyId];
  if (typeof enclosureWrapped !== "string") {
    throw new Error(
      `open: recipient ${input.recipientKeyId} not in enclosure_recipients`,
    );
  }
  const kEnclosure = sealUnwrap(
    input.suite,
    input.recipientPrivateKey,
    input.recipientPublicKey,
    enclosureWrapped,
  );

  const enclBlob = base64Decode(env.enclosure);
  if (enclBlob.length < 12) {
    throw new Error("open: enclosure blob too short");
  }
  const enclNonce = enclBlob.slice(0, 12);
  const enclCT = enclBlob.slice(12);
  const enclPT = aeadOpen(aead, kEnclosure, enclNonce, enclCT, postmarkID);
  return JSON.parse(new TextDecoder().decode(enclPT));
}

// ---------------------------------------------------------------------------
// Helpers

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function base64Encode(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < b.length; i++) {
    bin += String.fromCharCode(b[i] ?? 0);
  }
  return btoa(bin);
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
