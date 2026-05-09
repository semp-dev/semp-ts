/**
 * Staged-delivery partition computation per DELIVERY.md §3.2.1.
 *
 * Given a user's device directory, the per-device scoped
 * certificates, the set of device public keys for which an inbound
 * envelope's seal carries an enclosure-recipient wrap, and the
 * sender address, returns the slice of {@link StagedHeldStage}
 * values the staging runner feeds into the held-envelope queue.
 *
 * @module
 */

import type { AddressIdentity } from "../keys/device_certificate.js";
import type { DeviceCertificate } from "../keys/device_certificate.js";
import type { DeviceDirectory } from "../keys/device_records.js";
import { scopeAllowsSender } from "../keys/device_certificate.js";

import type { StagedHeldStage } from "./disposition.js";

/**
 * Lookup hook the partition routine calls for each delegated
 * device's scoped certificate. Returning `null` is treated as "no
 * current cert"; the device is excluded from the partition (the
 * spec's effect of certificate revocation per §10.3.7.3 step 3:
 * "stop delivering inbound envelopes to device_id").
 */
export type CertificateProvider = (deviceId: string) => DeviceCertificate | null;

/** Inputs to {@link partitionStages}. */
export interface PartitionInput {
  /**
   * The user's current device directory. {@link partitionStages}
   * iterates `directory.devices` to enumerate the account's
   * devices.
   */
  directory: DeviceDirectory;
  /**
   * Supplies the scoped certificate for each delegated device.
   * Called for every device whose role is `delegated`; full-access
   * devices have no certificate.
   */
  certificateProvider: CertificateProvider;
  /**
   * Set of device public keys for which the envelope's seal carries
   * an enclosure-recipient wrap. Only devices whose `device_public_key`
   * is in this set are eligible for delivery. Pubkeys are compared
   * verbatim against `DeviceDirectoryEntry.device_public_key` (the
   * same base64 form the directory uses).
   */
  enclosureRecipients: Set<string>;
  /**
   * The `brief.from` address the receive matcher evaluates against
   * per §10.3.4 "for receive, a peer is the sender address of an
   * inbound envelope after the home server has decrypted the brief".
   */
  senderAddress: AddressIdentity;
}

/**
 * Compute the §3.2.1 stage partition for an inbound envelope.
 *
 * Algorithm:
 *
 *  1. Walk the directory; for each device whose pubkey is in
 *     `enclosureRecipients`:
 *     - Full-access devices are deferred (their stage is computed
 *       implicitly per §10.3.3.1: `max(delegated_stages) + 1`).
 *     - Delegated devices are evaluated against their scoped cert:
 *       fetch the cert, run `scope.receive` against `senderAddress`.
 *       Devices whose receive matcher rejects the envelope (mode,
 *       allow/deny, or rate limit at the matcher level) are
 *       excluded from the partition entirely.
 *  2. Compute the implicit full-access stage as
 *     `max(delegated_stages_with_mode_not_none) + 1`, taken across
 *     ALL delegates with `receive.mode !== "none"` — not just those
 *     that allowed THIS envelope. Matches §10.3.3.1's "the maximum
 *     is taken over all delegated devices of the account that have
 *     a receive matcher whose mode is not none". When no such
 *     delegate exists, full-access devices are at stage 1 and
 *     staging is a no-op.
 *  3. Group eligible devices by stage and emit a sorted, monotonic
 *     `StagedHeldStage[]`. Stages with no devices are pruned.
 *
 * Does NOT consult §10.3.3.3 rate-limit counters; rate-limit gating
 * is the caller's concern. The matcher mode and allow/deny ARE
 * checked.
 *
 * Returns an empty array when no eligible devices remain (the
 * envelope is undeliverable to any device of the account; the
 * caller surfaces this as silent or rejected per its own policy).
 */
export function partitionStages(input: PartitionInput): StagedHeldStage[] {
  const eligible: { deviceId: string; stage: number }[] = [];
  const fullAccessIds: string[] = [];
  let maxDelegateMode = 0;

  for (const dev of input.directory.devices) {
    const recipientWanted = input.enclosureRecipients.has(
      dev.device_public_key,
    );

    if (dev.role === "full_access") {
      if (recipientWanted) {
        fullAccessIds.push(dev.device_id);
      }
      continue;
    }
    // Delegated device.
    const cert = input.certificateProvider(dev.device_id);
    if (cert === null) {
      // No current cert: per §10.3.7.3 step 3, stop delivering.
      continue;
    }
    // max-stage tally first: every delegate whose mode is not "none"
    // contributes to the implicit full-access stage, even if its
    // allow/deny rejects THIS envelope.
    if (cert.scope.receive.mode !== "none") {
      const stage = cert.scope.receive.delivery_stage ?? 0;
      if (stage > maxDelegateMode) {
        maxDelegateMode = stage;
      }
    }
    if (!recipientWanted) {
      continue;
    }
    if (cert.scope.receive.mode === "none") {
      continue;
    }
    if (!scopeAllowsSender(cert.scope.receive, input.senderAddress)) {
      // Sender does not pass the matcher; exclude per §3.2.1.
      continue;
    }
    let stage = cert.scope.receive.delivery_stage ?? 0;
    if (stage < 1) {
      // Defensive: a delegated cert without a stage gets stage 1 so
      // it does not collide with the full-access implicit stage.
      stage = 1;
    }
    eligible.push({ deviceId: dev.device_id, stage });
  }

  // Implicit full-access stage per §10.3.3.1 / §3.2.1.
  const fullAccessStage = maxDelegateMode > 0 ? maxDelegateMode + 1 : 1;
  for (const id of fullAccessIds) {
    eligible.push({ deviceId: id, stage: fullAccessStage });
  }

  if (eligible.length === 0) {
    return [];
  }

  // Group by stage, then emit a sorted slice.
  const byStage = new Map<number, string[]>();
  for (const e of eligible) {
    const list = byStage.get(e.stage);
    if (list === undefined) {
      byStage.set(e.stage, [e.deviceId]);
    } else {
      list.push(e.deviceId);
    }
  }
  const stages = Array.from(byStage.keys()).sort((a, b) => a - b);
  const out: StagedHeldStage[] = [];
  for (const s of stages) {
    const ids = byStage.get(s)!.slice().sort();
    out.push({
      stage: s,
      pending_device_ids: ids,
      dispositions: [],
    });
  }
  return out;
}
