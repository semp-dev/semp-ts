/**
 * Resume end-to-end test. Drive resumeClient + resumeServer
 * concurrently over the in-memory transport, assert both sides
 * arrive at identical session keys derived from the SAME
 * K_resumption, fresh ephemeral, and fresh nonces.
 *
 * @module
 */

import { describe, expect, test } from "vitest";

import { computeMAC } from "../crypto/index.js";
import { publicKeyFromSeed } from "../keys/index.js";
import { newMemoryPair } from "../transport/index.js";

import { HandshakeRejectedError } from "../handshake/driver.js";
import { resumeClient, resumeServer } from "./resume.js";

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function encodeBase64(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

describe("session.resume", () => {
  test("resume end-to-end: both peers derive identical session keys", async () => {
    const [tClient, tServer] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);
    // Shared K_resumption from the prior session.
    const kResumption = randomBytes(32);
    const ticket = "ticket-from-prior-session";

    const newSessionId = "01J7RESUMED0000000000000000";
    const newTicket = { value: "fresh-ticket-bytes", expires_at: "2026-12-31T23:59:59Z" };

    const [clientSession, serverSession] = await Promise.all([
      resumeClient(tClient, {
        serverDomainPub,
        transport: "memory",
        kResumption,
        resumptionTicket: ticket,
      }),
      resumeServer(tServer, {
        serverDomainSigningSeed: serverSeed,
        lookupTicket: (t) => {
          if (t === ticket) {
            return { ok: true, kResumption, permissions: ["send", "receive"] };
          }
          return { ok: false, reasonCode: "resumption_failed" };
        },
        generateNewTicket: () => newTicket,
        generateSessionId: () => newSessionId,
        sessionTTL: 300,
      }),
    ]);

    expect(clientSession.sessionId).toBe(newSessionId);
    expect(serverSession.sessionId).toBe(newSessionId);
    expect(clientSession.role).toBe("client");
    expect(serverSession.role).toBe("server");
    expect(clientSession.resumptionTicket).toEqual(newTicket);
    expect(serverSession.resumptionTicket).toEqual(newTicket);

    // Identical session keys (the gating interop check).
    expect(encodeBase64(clientSession.keys.encC2S)).toBe(
      encodeBase64(serverSession.keys.encC2S),
    );
    expect(encodeBase64(clientSession.keys.envMAC)).toBe(
      encodeBase64(serverSession.keys.envMAC),
    );

    // Sanity: symmetric MAC works post-resume.
    const sample = new TextEncoder().encode("post-resume envelope sample");
    expect(encodeBase64(computeMAC(clientSession.keys.envMAC, sample))).toBe(
      encodeBase64(computeMAC(serverSession.keys.envMAC, sample)),
    );

    await Promise.all([clientSession.erase(), serverSession.erase()]);
  });

  test("server rejects unknown ticket; client raises HandshakeRejectedError", async () => {
    const [tClient, tServer] = newMemoryPair();
    const serverSeed = randomBytes(32);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    const [clientResult, serverResult] = await Promise.allSettled([
      resumeClient(tClient, {
        serverDomainPub,
        transport: "memory",
        kResumption: randomBytes(32),
        resumptionTicket: "unknown-ticket",
      }),
      resumeServer(tServer, {
        serverDomainSigningSeed: serverSeed,
        lookupTicket: () => ({ ok: false, reasonCode: "resumption_failed" }),
        generateNewTicket: () => ({ value: "x", expires_at: "2026-12-31T00:00:00Z" }),
        generateSessionId: () => "x",
        sessionTTL: 300,
      }),
    ]);

    expect(clientResult.status).toBe("rejected");
    if (clientResult.status === "rejected") {
      expect(clientResult.reason).toBeInstanceOf(HandshakeRejectedError);
      const err = clientResult.reason as HandshakeRejectedError;
      expect(err.reasonCode).toBe("resumption_failed");
    }
    expect(serverResult.status).toBe("rejected");
  });
});
