import { describe, expect, it } from "vitest";

import {
  hybridDecapsulate,
  hybridEncapsulate,
  hybridEncapsulateWithRandomness,
  hybridGenerateKeyPair,
} from "./kem.js";

describe("hybridEncapsulateWithRandomness", () => {
  it("is deterministic and round-trips through hybridDecapsulate", () => {
    const recipient = hybridGenerateKeyPair();
    const m = new Uint8Array(32);
    const xPriv = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      m[i] = i;
      xPriv[i] = 0xff - i;
    }
    const a = hybridEncapsulateWithRandomness(recipient.publicKey, {
      kyberEncapsRandomnessM: m,
      ephemeralX25519Priv: xPriv,
    });
    const b = hybridEncapsulateWithRandomness(recipient.publicKey, {
      kyberEncapsRandomnessM: m,
      ephemeralX25519Priv: xPriv,
    });
    expect(a.ciphertext).toEqual(b.ciphertext);
    expect(a.sharedSecret).toEqual(b.sharedSecret);
    const recovered = hybridDecapsulate(a.ciphertext, recipient.secretKey);
    expect(recovered).toEqual(a.sharedSecret);
  });

  it("produces a different ciphertext from the fresh-randomness path", () => {
    const recipient = hybridGenerateKeyPair();
    const m = new Uint8Array(32);
    const xPriv = new Uint8Array(32);
    m[0] = 1;
    xPriv[0] = 1;
    const pinned = hybridEncapsulateWithRandomness(recipient.publicKey, {
      kyberEncapsRandomnessM: m,
      ephemeralX25519Priv: xPriv,
    });
    const fresh = hybridEncapsulate(recipient.publicKey);
    expect(pinned.ciphertext).not.toEqual(fresh.ciphertext);
    expect(
      hybridDecapsulate(fresh.ciphertext, recipient.secretKey),
    ).toEqual(fresh.sharedSecret);
  });

  it("rejects malformed inputs", () => {
    const recipient = hybridGenerateKeyPair();
    expect(() =>
      hybridEncapsulateWithRandomness(recipient.publicKey, {
        kyberEncapsRandomnessM: new Uint8Array(16),
        ephemeralX25519Priv: new Uint8Array(32),
      }),
    ).toThrow(/kyberEncapsRandomnessM/);
    expect(() =>
      hybridEncapsulateWithRandomness(recipient.publicKey, {
        kyberEncapsRandomnessM: new Uint8Array(32),
        ephemeralX25519Priv: new Uint8Array(16),
      }),
    ).toThrow(/ephemeralX25519Priv/);
    expect(() =>
      hybridEncapsulateWithRandomness(new Uint8Array(8), {
        kyberEncapsRandomnessM: new Uint8Array(32),
        ephemeralX25519Priv: new Uint8Array(32),
      }),
    ).toThrow(/remote pub/);
  });
});
