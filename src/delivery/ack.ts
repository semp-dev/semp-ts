/**
 * Per-attempt delivery acknowledgment objects per DELIVERY.md §1.
 *
 * A recipient server returns exactly one of three acknowledgments
 * for every envelope delivery attempt:
 *
 *   - `delivered`  - accepted; carries a signed
 *     {@link "./receipt".DeliveryReceipt} per §1.1.1, MAY include a
 *     {@link RecipientStatus} per §1.6 if the sender matches the
 *     recipient's visibility rules.
 *   - `rejected`   - explicitly refused with a reason code per §1.2.
 *   - `silent`     - no response within the sender's timeout window
 *     per §1.3. The wire form for silent is "no response sent at
 *     all"; this module exposes a constant value the sending server
 *     uses internally to record the outcome on its own queue state.
 *
 * The {@link DeliveryAck} JSON shape is what the recipient server
 * places in its response body (§1.1.1.5 example).
 *
 * @module
 */

import type { ReasonCode } from "../reasoncodes.js";

import type { DeliveryReceipt } from "./receipt.js";

/** The three protocol-level outcomes per §1.1. */
export type Acknowledgment = "delivered" | "rejected" | "silent";

/** Per-§1.6.3 recipient state values. */
export type RecipientState = "available" | "away" | "do_not_disturb";

/** Per-§1.6.4 visibility modes. */
export type VisibilityMode =
  | "everyone"
  | "domains"
  | "servers"
  | "users"
  | "nobody";

/** One entry in a {@link Visibility} allow list. */
export interface VisibilityEntry {
  /** Entry kind. The mode constrains which kinds are honored. */
  type: "domain" | "server" | "user";
  /** For `type: "domain"`. */
  domain?: string;
  /** For `type: "server"`. */
  server?: string;
  /** For `type: "user"`: full address. */
  address?: string;
}

/** Visibility configuration per §1.6.4. */
export interface Visibility {
  mode: VisibilityMode;
  /** Allow list. Entries whose `type` does not match `mode` are ignored. */
  allow?: VisibilityEntry[];
}

/**
 * Optional recipient status object included in `delivered`
 * acknowledgments per §1.6.1.
 */
export interface RecipientStatus {
  state: RecipientState;
  /** Freetext, max 256 UTF-8 bytes. */
  message?: string;
  /** ISO 8601 UTC timestamp. */
  until?: string;
}

/** Maximum length of {@link RecipientStatus.message} per §1.6.2. */
export const MaxStatusMessageBytes = 256;

/**
 * Per-attempt acknowledgment body returned inline by a recipient
 * server, per §1.1.1.5 / §1.6.1. Exactly one of:
 *
 *   - acknowledgment="delivered" with `receipt` populated and an
 *     optional `recipient_status`;
 *   - acknowledgment="rejected" with `reason_code` populated and an
 *     optional `reason`.
 *
 * The `silent` outcome is not represented on the wire - the
 * recipient simply does not respond.
 */
export interface DeliveryAck {
  acknowledgment: Exclude<Acknowledgment, "silent">;
  receipt?: DeliveryReceipt;
  recipient_status?: RecipientStatus;
  reason_code?: ReasonCode;
  reason?: string;
}

/**
 * Build a `delivered` ack from a signed receipt and optional
 * recipient status. Per §1.6.4 the caller is responsible for
 * deciding whether `recipientStatus` should be attached at all
 * (call {@link matchVisibility} first).
 */
export function buildDeliveredAck(
  receipt: DeliveryReceipt,
  recipientStatus?: RecipientStatus,
): DeliveryAck {
  const ack: DeliveryAck = {
    acknowledgment: "delivered",
    receipt,
  };
  if (recipientStatus !== undefined) {
    ack.recipient_status = recipientStatus;
  }
  return ack;
}

/** Build a `rejected` ack with a reason code and optional reason text. */
export function buildRejectedAck(
  reasonCode: ReasonCode,
  reason?: string,
): DeliveryAck {
  const ack: DeliveryAck = {
    acknowledgment: "rejected",
    reason_code: reasonCode,
  };
  if (reason !== undefined && reason !== "") {
    ack.reason = reason;
  }
  return ack;
}

/**
 * Sender-identity inputs for {@link matchVisibility}. All three
 * fields are optional; an empty value disables matching for the
 * corresponding entry type.
 */
export interface SenderIdentity {
  /** Full sender address (e.g., `alice@example.com`). */
  address?: string;
  /** Sender domain (e.g., `example.com`). */
  domain?: string;
  /** Routing server hostname when known. */
  server?: string;
}

/**
 * Resolve visibility per §1.6.4. Returns true when the
 * recipient_status should be attached to the acknowledgment.
 *
 *  - `nobody` (default): never disclose, regardless of the allow list.
 *  - `everyone`: always disclose, regardless of the allow list.
 *  - `domains` / `servers` / `users`: walk the allow list looking for
 *    a match. The mode constrains which entry kinds are honored - in
 *    `domains` mode only entries with `type: "domain"`, etc.
 *    Mismatched entries in the allow list are ignored.
 *
 * All comparisons are case-insensitive. Multiple rules combine as a
 * union: any matching entry returns true.
 *
 * A nil/undefined visibility (no configuration at all) is equivalent
 * to mode=nobody.
 */
export function matchVisibility(
  visibility: Visibility | undefined,
  sender: SenderIdentity,
): boolean {
  if (visibility === undefined) {
    return false;
  }
  switch (visibility.mode) {
    case "nobody":
      return false;
    case "everyone":
      return true;
    case "domains":
    case "servers":
    case "users":
      break;
    default:
      // Unknown mode - fail closed.
      return false;
  }

  const senderAddress = (sender.address ?? "").toLowerCase();
  const senderDomain = (sender.domain ?? "").toLowerCase();
  const senderServer = (sender.server ?? "").toLowerCase();
  const allow = visibility.allow ?? [];

  for (const entry of allow) {
    switch (entry.type) {
      case "domain":
        if (visibility.mode !== "domains") {
          continue;
        }
        if (
          senderDomain !== "" &&
          (entry.domain ?? "").toLowerCase() === senderDomain
        ) {
          return true;
        }
        break;
      case "server":
        if (visibility.mode !== "servers") {
          continue;
        }
        if (
          senderServer !== "" &&
          (entry.server ?? "").toLowerCase() === senderServer
        ) {
          return true;
        }
        break;
      case "user":
        if (visibility.mode !== "users") {
          continue;
        }
        if (
          senderAddress !== "" &&
          (entry.address ?? "").toLowerCase() === senderAddress
        ) {
          return true;
        }
        break;
      default:
        // Unknown entry type - skip.
        break;
    }
  }
  return false;
}

/**
 * Validate a {@link RecipientStatus} per §1.6.2: the `message` field
 * MUST NOT exceed 256 UTF-8 bytes, and `state` MUST be one of the
 * three documented values. Throws on the first violation.
 */
export function validateRecipientStatus(s: RecipientStatus): void {
  if (s.state !== "available" && s.state !== "away" && s.state !== "do_not_disturb") {
    throw new Error(`recipient_status: invalid state ${JSON.stringify(s.state)}`);
  }
  if (s.message !== undefined) {
    const byteLen = new TextEncoder().encode(s.message).length;
    if (byteLen > MaxStatusMessageBytes) {
      throw new Error(
        `recipient_status: message exceeds ${MaxStatusMessageBytes} UTF-8 bytes (${byteLen})`,
      );
    }
  }
}
