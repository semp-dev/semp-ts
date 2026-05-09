/**
 * SEMP_INTERNAL_ROUTE wire shapes per DISCOVERY.md §5.4.
 *
 * Used when one partition server hands an envelope to a sibling
 * partition server inside the same domain.
 *
 * Internal routing does NOT exempt an envelope from the delivery
 * pipeline or from block-list enforcement; the receiving partition
 * server runs the full pipeline before producing its acknowledgment
 * (DELIVERY.md §5.3).
 *
 * @module
 */

import type { Envelope } from "../envelope/index.js";

import type { Acknowledgment } from "./ack.js";

/** Wire-level type discriminator. */
export const InternalRouteType = "SEMP_INTERNAL_ROUTE";

/** Schema version. */
export const InternalRouteVersion = "1.0.0";

/**
 * Recommended timeout for internally routed deliveries before they
 * are treated as silent (DISCOVERY.md §5.4.1, DELIVERY.md §1.5).
 */
export const InternalRouteTimeoutMs = 30_000;

/** SEMP_INTERNAL_ROUTE request envelope per §5.4. */
export interface InternalRoute {
  type: typeof InternalRouteType;
  to: string;
  internal_route: string[];
  /** ISO 8601 UTC. */
  timestamp: string;
  envelope: Envelope;
}

/**
 * Acknowledgment a receiving partition server returns for every
 * internally routed envelope per §5.4.1.
 */
export interface InternalRouteAck {
  type: typeof InternalRouteType;
  step: "acknowledgment";
  version: string;
  envelope_id: string;
  to: string;
  status: Acknowledgment;
  reason_code?: string;
  reason?: string;
  /** ISO 8601 UTC. */
  timestamp: string;
}
