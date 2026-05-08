/**
 * Retry-schedule primitives per DELIVERY.md §2.2 + §2.3 + §2.4.
 *
 * Exposes the bounds the spec sets on retry timing (initial
 * interval, multiplier, max interval, jitter, attempt floor),
 * computes the base + jittered interval for a given attempt, and
 * enforces the §2.3 recoverable-reason classification.
 *
 * @module
 */

import type { ReasonCode } from "../reasoncodes.js";

/** Minimum first base interval per §2.3 (60 seconds). */
export const MinRetryInitialIntervalMs = 60_000;

/** Minimum exponential backoff multiplier per §2.3. */
export const MinRetryMultiplier = 2.0;

/** Cap on individual inter-attempt intervals per §2.3 (6 hours). */
export const MaxRetryIntervalMs = 6 * 60 * 60 * 1000;

/** Minimum jitter half-width per §2.3 (10% — RECOMMENDED 25%). */
export const MinRetryJitterFraction = 0.10;

/**
 * Lower bound on the realized jittered interval per §2.3:
 * jitter MUST NOT reduce below 50% of the first base interval.
 */
export const MinJitterFloorMs = MinRetryInitialIntervalMs / 2;

/** Minimum number of retry attempts per §2.3. */
export const MinRetryAttempts = 5;

/** Default `server_max_retry_horizon` per §2.4 (72 hours). */
export const DefaultMaxRetryHorizonMs = 72 * 60 * 60 * 1000;

/** Hard ceiling on `server_max_retry_horizon` per §2.4 (7 days). */
export const MaxRetryHorizonCapMs = 7 * 24 * 60 * 60 * 1000;

/** Operator-tunable retry policy. Zero / out-of-bounds values clamp to spec minima. */
export interface RetryConfig {
  /** First base interval. Defaults to {@link MinRetryInitialIntervalMs}. */
  initialIntervalMs?: number;
  /** Exponential backoff factor. Defaults to {@link MinRetryMultiplier}. */
  multiplier?: number;
  /** Cap on individual base intervals. Defaults to {@link MaxRetryIntervalMs}. */
  maxIntervalMs?: number;
  /** Symmetric jitter half-width. Defaults to {@link MinRetryJitterFraction}. */
  jitterFraction?: number;
}

/** Effective {@link RetryConfig} after applying spec minima/maxima. */
export interface EffectiveRetryConfig {
  initialIntervalMs: number;
  multiplier: number;
  maxIntervalMs: number;
  jitterFraction: number;
}

/** Apply spec minima/maxima to `cfg` and return the effective values. */
export function sanitizeRetry(cfg: RetryConfig): EffectiveRetryConfig {
  const initialIntervalMs = Math.max(
    cfg.initialIntervalMs ?? 0,
    MinRetryInitialIntervalMs,
  );
  const multiplier = Math.max(cfg.multiplier ?? 0, MinRetryMultiplier);
  let maxIntervalMs = cfg.maxIntervalMs ?? 0;
  if (maxIntervalMs <= 0 || maxIntervalMs > MaxRetryIntervalMs) {
    maxIntervalMs = MaxRetryIntervalMs;
  }
  const jitterFraction = Math.max(
    cfg.jitterFraction ?? 0,
    MinRetryJitterFraction,
  );
  return { initialIntervalMs, multiplier, maxIntervalMs, jitterFraction };
}

/**
 * Unjittered base interval for the zero-indexed `attempt`. Computes
 * `initialInterval * multiplier^attempt`, clamped to `maxIntervalMs`.
 */
export function baseIntervalMs(
  cfg: RetryConfig,
  attempt: number,
): number {
  const eff = sanitizeRetry(cfg);
  const a = Math.max(0, Math.floor(attempt));
  let d = eff.initialIntervalMs;
  for (let i = 0; i < a; i++) {
    d *= eff.multiplier;
    if (d > eff.maxIntervalMs) {
      d = eff.maxIntervalMs;
      break;
    }
  }
  return Math.min(d, eff.maxIntervalMs);
}

/**
 * Apply symmetric jitter to `baseMs` using a random multiplier in
 * `[1-j, 1+j]`, floored at {@link MinJitterFloorMs}. Uses
 * `globalThis.crypto.getRandomValues` for entropy by default.
 */
export function jitterIntervalMs(
  cfg: RetryConfig,
  baseMs: number,
  rand: () => number = defaultRandFloat,
): number {
  const eff = sanitizeRetry(cfg);
  if (baseMs <= 0) {
    throw new Error("delivery: non-positive base interval");
  }
  const r = rand();
  if (r < 0 || r >= 1) {
    throw new Error("delivery: jitter random source returned out-of-range value");
  }
  const m = 1 - eff.jitterFraction + 2 * eff.jitterFraction * r;
  const jittered = Math.floor(baseMs * m);
  return Math.max(jittered, MinJitterFloorMs);
}

/**
 * Compute the wall-clock time of the next attempt:
 * `previous + jitter(base(cfg, attempt))`.
 */
export function nextAttemptAt(
  cfg: RetryConfig,
  previous: Date,
  attempt: number,
  rand: () => number = defaultRandFloat,
): Date {
  if (Number.isNaN(previous.getTime())) {
    throw new Error("delivery: previous attempt time is invalid");
  }
  const base = baseIntervalMs(cfg, attempt);
  const jittered = jitterIntervalMs(cfg, base, rand);
  return new Date(previous.getTime() + jittered);
}

/**
 * Report whether `reasonCode` permits retry per §2.3 / ERRORS.md
 * §3. Unknown reason codes default to non-recoverable.
 */
export function isRecoverableReason(reasonCode: string): boolean {
  switch (reasonCode as ReasonCode | string) {
    case "handshake_invalid":
    case "handshake_expired":
    case "no_session":
    case "server_unavailable":
    case "rate_limited":
    case "server_at_capacity":
      return true;
    default:
      return false;
  }
}

/**
 * Effective delivery deadline per §2.4 — the earlier of
 * `postmark.expires` and `queuedAt + horizon`. `horizon <= 0`
 * defaults to {@link DefaultMaxRetryHorizonMs}; values larger than
 * {@link MaxRetryHorizonCapMs} clamp down.
 */
export function effectiveDeadline(
  postmarkExpires: Date | null,
  queuedAt: Date,
  horizonMs?: number,
): Date {
  let h = horizonMs ?? 0;
  if (h <= 0) {
    h = DefaultMaxRetryHorizonMs;
  }
  if (h > MaxRetryHorizonCapMs) {
    h = MaxRetryHorizonCapMs;
  }
  const horizonDeadline = new Date(queuedAt.getTime() + h);
  if (postmarkExpires === null) {
    return horizonDeadline;
  }
  return postmarkExpires.getTime() < horizonDeadline.getTime()
    ? postmarkExpires
    : horizonDeadline;
}

function defaultRandFloat(): number {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return (buf[0] ?? 0) / 0x1_0000_0000;
}
