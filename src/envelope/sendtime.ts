/**
 * Send-time obfuscation delay per CLIENT.md §3.8.
 *
 * `sendTimeDelay` sleeps for a uniformly random interval in
 * `[0, ceilingMs]` before resolving, reducing the temporal
 * resolution available to a passive network observer correlating
 * the sender's submission with the recipient's delivery.
 *
 * Honors `postmark.expires`: the drawn delay is clamped so that
 * submission cannot push past the envelope's expiry window.
 *
 * @module
 */

import type { Envelope } from "./compose.js";

/** RECOMMENDED upper bound on the randomized delay per §3.8.1. */
export const DefaultSendTimeDelayCeilingMs = 60_000;

/** Inputs to {@link sendTimeDelay}. */
export interface SendTimeDelayConfig {
  /** Upper bound on the delay in ms. Zero / undefined means no delay. */
  ceilingMs?: number;
  /**
   * When true, skip the delay entirely. Clients flag time-sensitive
   * envelopes (a verification code the user is reading, a reply in a
   * live conversation, etc.) per §3.8.1.
   */
  timeSensitive?: boolean;
  /** Wall-clock provider. Defaults to `() => new Date()`. */
  nowFn?: () => Date;
  /** Cancellation signal. Aborts the delay early when fired. */
  signal?: AbortSignal;
  /**
   * Random source returning a float in `[0, 1)`. Defaults to
   * `globalThis.crypto.getRandomValues`-derived entropy.
   */
  rand?: () => number;
}

/**
 * Sleep for a uniformly random interval in `[0, ceilingMs]` before
 * resolving. Returns immediately when:
 *
 *  - `cfg.timeSensitive === true`
 *  - `cfg.ceilingMs` is zero / undefined / negative
 *  - the drawn delay rounds to zero
 *
 * Throws when the envelope is already expired (`postmark.expires`
 * is in the past).
 */
export async function sendTimeDelay(
  env: Envelope,
  cfg: SendTimeDelayConfig = {},
): Promise<void> {
  if (cfg.timeSensitive === true) {
    return;
  }
  let ceiling = cfg.ceilingMs ?? 0;
  if (ceiling <= 0) {
    return;
  }
  const nowFn = cfg.nowFn ?? (() => new Date());
  const expiresStr = env.postmark.expires;
  if (typeof expiresStr === "string" && expiresStr !== "") {
    const expiresMs = Date.parse(expiresStr);
    if (Number.isNaN(expiresMs)) {
      throw new Error(
        `envelope: postmark.expires ${JSON.stringify(expiresStr)} is not ISO 8601`,
      );
    }
    const window = expiresMs - nowFn().getTime();
    if (window <= 0) {
      throw new Error(
        `envelope: cannot delay an already-expired envelope (expires ${expiresStr})`,
      );
    }
    if (window < ceiling) {
      ceiling = window;
    }
  }

  const rand = cfg.rand ?? defaultRandFloat;
  const r = rand();
  if (r < 0 || r >= 1) {
    throw new Error("envelope: send-time random source out of range");
  }
  const delay = Math.floor(r * ceiling);
  if (delay <= 0) {
    return;
  }

  await sleep(delay, cfg.signal);
}

function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(signal.reason ?? new Error("envelope: send-time delay aborted"));
      return;
    }
    const t = setTimeout(() => {
      if (signal !== undefined) {
        signal.removeEventListener("abort", onAbort);
      }
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(t);
      reject(signal?.reason ?? new Error("envelope: send-time delay aborted"));
    };
    if (signal !== undefined) {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

function defaultRandFloat(): number {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return (buf[0] ?? 0) / 0x1_0000_0000;
}
