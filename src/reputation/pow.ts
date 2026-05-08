/**
 * Proof-of-Work challenge primitives per REPUTATION.md §8.3.
 *
 * The handshake layer carries the actual SHA-256 PoW solver +
 * verifier (see `handshake/pow.ts`). This module supplies the
 * issuer-side helpers: difficulty selection, challenge minting, and
 * a single-use redemption ledger that prevents replay per §8.3.4.
 *
 * @module
 */

import type { Assessment } from "./types.js";

/** Only supported PoW hash algorithm. */
export const PoWAlgorithm = "sha256";

/** Minimum entropy a challenge prefix must carry per §8.3.1. */
export const MinPrefixBytes = 16;

/** RECOMMENDED challenge TTL per §8.3.4. */
export const DefaultChallengeTTLMs = 5 * 60 * 1000;

/** Difficulty presets per §8.3.2. */
export const DifficultyBaseline = 20;
export const DifficultyRelaxed = 16;
export const DifficultySuspicious = 22;
export const DifficultyHostile = 26;

/** New-domain age gate per §2.1: domains younger than this get scrutiny. */
export const DomainAgeGateDays = 30;

/** A challenge minted by the recipient server per §8.3.1. */
export interface PoWChallenge {
  /** ULID-shaped 26-character Crockford base32 string. */
  id: string;
  algorithm: typeof PoWAlgorithm;
  /** ≥ {@link MinPrefixBytes} bytes of entropy. */
  prefix: Uint8Array;
  /** Leading zero bits required in the solution hash. */
  difficulty: number;
  /** Single-use deadline. */
  expires: Date;
}

/**
 * Difficulty for a zero-reputation, age-known domain per §8.3.2:
 *  - age < {@link DomainAgeGateDays} → DifficultyBaseline (20)
 *  - age ≥ DomainAgeGateDays → DifficultyRelaxed (16)
 */
export function difficultyForAge(ageDays: number): number {
  return ageDays < DomainAgeGateDays ? DifficultyBaseline : DifficultyRelaxed;
}

/**
 * Difficulty for a domain whose reputation has been summarized as
 * `assessment` per §8.3.2:
 *  - "trusted" / "neutral" / "" → 0 (no PoW required)
 *  - "suspicious"               → DifficultySuspicious (22)
 *  - "hostile"                  → DifficultyHostile (26)
 *
 * A return of 0 MUST be interpreted as "no challenge required".
 */
export function difficultyForAssessment(a: Assessment | ""): number {
  switch (a) {
    case "":
    case "trusted":
    case "neutral":
      return 0;
    case "suspicious":
      return DifficultySuspicious;
    case "hostile":
      return DifficultyHostile;
    default:
      return 0;
  }
}

/**
 * Construct a fresh challenge at `difficulty`, with
 * {@link MinPrefixBytes} bytes of fresh prefix entropy and a ULID
 * id derived from the current wall clock.
 *
 * `ttlMs <= 0` is replaced with {@link DefaultChallengeTTLMs}.
 */
export function issueChallenge(
  difficulty: number,
  ttlMs?: number,
  rand: (n: number) => Uint8Array = defaultRand,
): PoWChallenge {
  if (!Number.isInteger(difficulty) || difficulty < 0) {
    throw new Error("reputation: negative or non-integer PoW difficulty");
  }
  if (difficulty > 256) {
    throw new Error("reputation: PoW difficulty exceeds SHA-256 output size");
  }
  const ttl = ttlMs !== undefined && ttlMs > 0 ? ttlMs : DefaultChallengeTTLMs;
  return {
    id: newULID(rand),
    algorithm: PoWAlgorithm,
    prefix: rand(MinPrefixBytes),
    difficulty,
    expires: new Date(Date.now() + ttl),
  };
}

/** Base64-encoded challenge prefix — what the wire carries. */
export function challengePrefixBase64(c: PoWChallenge): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(c.prefix).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < c.prefix.length; i++) {
    bin += String.fromCharCode(c.prefix[i] ?? 0);
  }
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// Redemption ledger

/**
 * Tracks issued + redeemed challenges; prevents replay per §8.3.4.
 * Concurrency-safe under the JS single-thread model. Production
 * deployments wrap a durable backend.
 */
export class ChallengeLedger {
  private readonly entries = new Map<string, { challenge: PoWChallenge; redeemed: boolean }>();
  private lastSweep = 0;
  private readonly sweepIntervalMs: number;
  private readonly nowFn: () => Date;

  constructor(sweepIntervalMs = 60_000, nowFn: () => Date = () => new Date()) {
    this.sweepIntervalMs = sweepIntervalMs;
    this.nowFn = nowFn;
  }

  /** Register `c` so a later {@link redeem} call can find it. */
  record(c: PoWChallenge): void {
    if (c.id === "") {
      throw new Error("reputation: challenge id is empty");
    }
    if (this.entries.has(c.id)) {
      throw new Error(`reputation: challenge ${c.id} already recorded`);
    }
    this.entries.set(c.id, { challenge: c, redeemed: false });
    this.maybeSweep();
  }

  /**
   * Redeem the challenge with `id`. Returns the challenge on success.
   * Throws when:
   *  - the challenge is unknown
   *  - the challenge has already been redeemed
   *  - the challenge has expired
   */
  redeem(id: string): PoWChallenge {
    const e = this.entries.get(id);
    if (e === undefined) {
      throw new Error(`reputation: challenge ${id} not found`);
    }
    if (e.redeemed) {
      throw new Error(`reputation: challenge ${id} already used`);
    }
    if (this.nowFn().getTime() >= e.challenge.expires.getTime()) {
      // Drop expired entry now that we've checked it.
      this.entries.delete(id);
      throw new Error(`reputation: challenge ${id} has expired`);
    }
    e.redeemed = true;
    return e.challenge;
  }

  /** Number of currently-active (unredeemed, unexpired) entries. */
  active(): number {
    let n = 0;
    const now = this.nowFn().getTime();
    for (const e of this.entries.values()) {
      if (!e.redeemed && now < e.challenge.expires.getTime()) {
        n++;
      }
    }
    return n;
  }

  /** Force an immediate sweep of expired entries. */
  sweep(): void {
    this.sweepNow(this.nowFn().getTime());
  }

  private maybeSweep(): void {
    const now = this.nowFn().getTime();
    if (now - this.lastSweep >= this.sweepIntervalMs) {
      this.sweepNow(now);
    }
  }

  private sweepNow(nowMs: number): void {
    for (const [id, e] of this.entries) {
      if (nowMs >= e.challenge.expires.getTime()) {
        this.entries.delete(id);
      }
    }
    this.lastSweep = nowMs;
  }
}

// ---------------------------------------------------------------------------
// Helpers

function defaultRand(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function newULID(rand: (n: number) => Uint8Array): string {
  const bits = new Uint8Array(16);
  const ms = BigInt(Date.now());
  bits[0] = Number((ms >> 40n) & 0xffn);
  bits[1] = Number((ms >> 32n) & 0xffn);
  bits[2] = Number((ms >> 24n) & 0xffn);
  bits[3] = Number((ms >> 16n) & 0xffn);
  bits[4] = Number((ms >> 8n) & 0xffn);
  bits[5] = Number(ms & 0xffn);
  const random = rand(10);
  for (let i = 0; i < 10; i++) {
    bits[6 + i] = random[i] ?? 0;
  }
  let u = 0n;
  for (let i = 0; i < 8; i++) {
    u = (u << 8n) | BigInt(bits[i] ?? 0);
  }
  let u2 = 0n;
  for (let i = 8; i < 16; i++) {
    u2 = (u2 << 8n) | BigInt(bits[i] ?? 0);
  }
  const out = new Array<string>(26);
  for (let i = 25; i >= 13; i--) {
    out[i] = ULID_ALPHABET[Number(u2 & 31n)] ?? "0";
    u2 >>= 5n;
  }
  for (let i = 12; i >= 0; i--) {
    out[i] = ULID_ALPHABET[Number(u & 31n)] ?? "0";
    u >>= 5n;
  }
  return out.join("");
}
