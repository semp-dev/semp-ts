/**
 * Gossip-hash summary per REPUTATION.md §5.
 *
 * `computeGossipHash(domain, observations)` returns a stable digest
 * over (domain, [{id, timestamp}, ...]) so two observers with the
 * same observation set produce byte-identical hashes and can detect
 * divergence cheaply.
 *
 * The hash covers only ids + timestamps, not full metric bodies, so
 * a comparison remains meaningful when two observers report the
 * same underlying events with slightly different metrics. Callers
 * that want a full-body comparison walk the observations themselves.
 *
 * @module
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { marshal as canonicalMarshal } from "../canonical/index.js";

import type { GossipHash, Observation } from "./types.js";

/**
 * Compute the publishable {@link GossipHash} for `domain` given
 * `observations`. Throws when `domain` is empty. An empty
 * `observations` slice is allowed (legitimate "I have no
 * observations for this subject" publication).
 */
export function computeGossipHash(
  domain: string,
  observations: Observation[],
  now: Date = new Date(),
): GossipHash {
  if (domain.trim() === "") {
    throw new Error("reputation: gossip hash requires a domain");
  }
  // Stable order so two observers who hold the same set produce the
  // same hash regardless of internal iteration order.
  const entries = observations
    .map((o) => ({ id: o.id, timestamp: o.timestamp }))
    .sort((a, b) => {
      if (a.id !== b.id) {
        return a.id < b.id ? -1 : 1;
      }
      return a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0;
    });
  const payload = {
    domain: domain.trim().toLowerCase(),
    entries,
  };
  const canonical = canonicalMarshal(payload as unknown as Record<string, unknown>);
  const sum = sha256(canonical);
  return {
    domain: payload.domain,
    hash: bytesToHex(sum),
    algorithm: "sha256",
    as_of: isoSecond(now),
  };
}

function isoSecond(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function bytesToHex(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("hex");
  }
  let out = "";
  for (let i = 0; i < b.length; i++) {
    out += (b[i] ?? 0).toString(16).padStart(2, "0");
  }
  return out;
}
