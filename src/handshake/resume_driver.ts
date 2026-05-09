/**
 * Session-resume driver per HANDSHAKE.md §2.8.
 *
 * Wraps the stateful {@link HandshakeClient} for the resume path:
 *
 *   1. Send `step="resume"` with the ticket value + a fresh client
 *      nonce.
 *   2. Receive ACCEPTED (or REJECTED).
 *   3. On ACCEPTED, derive resumed session keys and return both
 *      the new session and the new ticket the server issued for
 *      chaining a future resume.
 *
 * On REJECTED with `reason_code` ∈ {`resumption_failed`,
 * `configuration_stale`, `no_session`}, throw an error that
 * satisfies {@link "./abort".isResumptionFailed}; the caller MUST
 * discard the resume attempt and fall back to a fresh full
 * handshake. {@link runClientResumeOrFull} composes this for callers
 * who want one-call fallback.
 *
 * @module
 */

import type { Transport } from "../transport/index.js";

import {
  type HandshakeClient,
  type HandshakeClientSession,
  HandshakeRejectedError,
} from "./client_state.js";
import { isResumptionFailed } from "./abort.js";

/**
 * Drive a client-side resume exchange to completion over `transport`.
 * Returns the resumed session plus the new ticket bytes the server
 * issued for chaining (`undefined` if the server didn't issue one).
 */
export async function runClientResume(
  transport: Transport,
  client: HandshakeClient,
  ticket: string,
): Promise<{ session: HandshakeClientSession; newTicket: string | undefined }> {
  if (ticket === "") {
    throw new Error("handshake: empty resumption ticket");
  }
  const resumeBytes = client.resume(ticket);
  await transport.send(resumeBytes);
  const respBytes = await transport.receive();
  if (respBytes === null) {
    throw new Error("handshake: connection closed waiting for resume response");
  }
  return client.onResumeAccepted(respBytes);
}

/**
 * Try a resume against `resumeTransport` / `resumeClient` /
 * `ticket` per §2.8.5. If the resume fails with a fallback-eligible
 * reason (resumption_failed / configuration_stale / no_session),
 * discard the resume attempt and perform a full handshake against a
 * fresh transport + client supplied by the caller.
 *
 * The caller supplies factories rather than reusing the prior
 * transport / client because:
 *
 *   - The prior transport was already used for the failed Resume
 *     exchange.
 *   - The prior client has accumulated state from `resume()` that
 *     would interfere with a fresh `init()`.
 *
 * Returns `{ session, newTicket, fellBack }`. `fellBack` is `true`
 * when the function fell back to a full handshake.
 */
export async function runClientResumeOrFull(
  resumeTransport: Transport,
  resumeClient: HandshakeClient,
  ticket: string,
  freshTransport: () => Promise<Transport>,
  fullHandshake: (
    transport: Transport,
  ) => Promise<HandshakeClientSession>,
): Promise<{
  session: HandshakeClientSession;
  newTicket: string | undefined;
  fellBack: boolean;
}> {
  try {
    const r = await runClientResume(resumeTransport, resumeClient, ticket);
    return { session: r.session, newTicket: r.newTicket, fellBack: false };
  } catch (err) {
    if (
      !(err instanceof HandshakeRejectedError) ||
      !isResumptionFailed(err)
    ) {
      throw err;
    }
    // Fall back to a full handshake on a fresh transport + client.
    const t = await freshTransport();
    const session = await fullHandshake(t);
    return { session, newTicket: undefined, fellBack: true };
  }
}
