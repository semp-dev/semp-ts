/**
 * Trust-gossip publication HTTP client per REPUTATION.md §5.1.
 *
 * Observers publish their {@link TrustObservations} envelopes at:
 *
 * ```
 * https://<observer>/.well-known/semp/reputation/<subject>
 * ```
 *
 * Fetching servers GET that URL, verify the envelope-level
 * signature, and use the inner observations to make trust
 * decisions. The fetcher is `fetch`-injectable so tests can stub
 * the HTTPS round-trip; production callers omit `fetchImpl` and the
 * fetcher uses Node 22+'s global `fetch`.
 *
 * @module
 */

import { type FetchLike } from "../discovery/index.js";

import { type TrustObservations, PublicationPath } from "./types.js";
import { verifyTrustObservations } from "./sign.js";

/**
 * Maximum body the fetcher accepts from a remote observer. 1 MiB is
 * enough for a substantial observation publication (hundreds of
 * inner records) without letting a hostile observer feed us
 * unbounded JSON.
 */
export const TrustGossipMaxBytes = 1 * 1024 * 1024;

/** Options to {@link fetchTrustObservations}. */
export interface FetchTrustObservationsOptions {
  /** Override the fetch implementation. Defaults to `globalThis.fetch`. */
  fetchImpl?: FetchLike;
  /** Optional cancellation signal. */
  signal?: AbortSignal;
  /**
   * Per-request timeout in milliseconds. Defaults to 10 seconds —
   * matches `discovery.fetchConfiguration`.
   */
  timeoutMs?: number;
  /**
   * Override the URL produced for `(observer, subject)`. Defaults to
   * `https://<observer>${PublicationPath}<subject>`. Tests use this
   * to point at an httptest server.
   */
  urlFn?: (observer: string, subject: string) => string;
  /**
   * Override the byte cap. Defaults to {@link TrustGossipMaxBytes}.
   */
  maxBytes?: number;
}

/**
 * GET the trust-gossip publication for `subject` from `observer`,
 * verify the envelope-level signature with `observerPub`, and
 * return the parsed envelope.
 *
 * Per-observation signatures inside `result.observations` are NOT
 * verified — callers walk those and call
 * {@link "./sign".verifyObservation} on each, because different
 * observations in the same envelope MAY be signed under different
 * key_ids (e.g. after a key rotation).
 *
 * Throws on transport failure, malformed JSON, body cap exceeded,
 * unsigned envelope, or signature mismatch.
 */
export async function fetchTrustObservations(
  observer: string,
  subject: string,
  observerPub: Uint8Array,
  opts: FetchTrustObservationsOptions = {},
): Promise<TrustObservations> {
  if (observer === "") {
    throw new Error("reputation: empty observer");
  }
  if (subject === "") {
    throw new Error("reputation: empty subject");
  }
  if (observerPub.length === 0) {
    throw new Error("reputation: empty observer public key");
  }
  const url =
    opts.urlFn !== undefined
      ? opts.urlFn(observer, subject)
      : `https://${observer}${PublicationPath}${encodeURIComponent(subject)}`;
  const fetchFn =
    opts.fetchImpl ?? (globalThis.fetch as FetchLike | undefined);
  if (fetchFn === undefined) {
    throw new Error(
      "reputation: no fetch implementation available (Node 22+ or pass fetchImpl)",
    );
  }
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    opts.timeoutMs ?? 10_000,
  );
  // Wire the caller's signal through too so external cancellation
  // propagates.
  let externalSubscribed = false;
  const onAbort = (): void => {
    controller.abort();
  };
  if (opts.signal !== undefined) {
    if (opts.signal.aborted) {
      controller.abort();
    } else {
      opts.signal.addEventListener("abort", onAbort, { once: true });
      externalSubscribed = true;
    }
  }
  let resp: Awaited<ReturnType<FetchLike>>;
  try {
    resp = await fetchFn(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
    if (externalSubscribed) {
      opts.signal!.removeEventListener("abort", onAbort);
    }
  }
  if (!resp.ok) {
    throw new Error(`reputation: ${url} returned HTTP ${resp.status}`);
  }
  const body = await resp.text();
  const cap = opts.maxBytes ?? TrustGossipMaxBytes;
  if (body.length > cap) {
    throw new Error(
      `reputation: trust gossip body exceeds ${cap} bytes (got ${body.length})`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(
      `reputation: parse trust observations: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("reputation: trust observations is not a JSON object");
  }
  const env = parsed as TrustObservations;
  if (!verifyTrustObservations(env, observerPub)) {
    throw new Error("reputation: trust observations signature did not verify");
  }
  return env;
}
