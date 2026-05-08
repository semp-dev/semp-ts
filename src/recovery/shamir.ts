/**
 * Shamir's Secret Sharing over GF(256) per RECOVERY.md §5.1 + §5.4.
 *
 * Operates one polynomial per secret byte; the polynomial constant
 * term is the secret byte and the higher coefficients are random.
 * Reconstruction uses Lagrange interpolation at x=0.
 *
 * GF(256) arithmetic uses the AES reduction polynomial 0x11b with
 * generator g = 3 (matches semp-go byte-for-byte; the recovery-shamir
 * vectors verify cross-language reproducibility).
 *
 * @module
 */

/** Minimum reconstruction threshold per §5.1. */
export const MinShamirThreshold = 2;

/** Maximum share count per §5.1. */
export const MaxShamirTotalShares = 16;

/** A single Shamir share. */
export interface ShamirShare {
  /** 1-based polynomial-evaluation x-coordinate. Index 0 IS the secret. */
  index: number;
  /** One byte per secret byte. */
  value: Uint8Array;
}

/**
 * Random source for split. `n` MUST be filled with cryptographically
 * strong bytes. Defaults to `globalThis.crypto.getRandomValues`.
 */
export type RandSource = (n: number) => Uint8Array;

const defaultRand: RandSource = (n) => {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
};

/**
 * Split `secret` into `totalShares` shares with reconstruction
 * threshold `threshold` per §5.1. Returns `totalShares` shares; any
 * `threshold` of them suffice.
 *
 * Bounds: `MinShamirThreshold <= threshold <= totalShares <=
 * MaxShamirTotalShares`.
 */
export function splitSecret(
  secret: Uint8Array,
  threshold: number,
  totalShares: number,
  rand: RandSource = defaultRand,
): ShamirShare[] {
  if (secret.length === 0) {
    throw new Error("recovery: split secret is empty");
  }
  if (!Number.isInteger(threshold) || threshold < MinShamirThreshold) {
    throw new Error(
      `recovery: threshold ${threshold} below minimum ${MinShamirThreshold}`,
    );
  }
  if (!Number.isInteger(totalShares) || totalShares < threshold) {
    throw new Error(
      `recovery: total_shares ${totalShares} below threshold ${threshold}`,
    );
  }
  if (totalShares > MaxShamirTotalShares) {
    throw new Error(
      `recovery: total_shares ${totalShares} above maximum ${MaxShamirTotalShares}`,
    );
  }

  const shares: ShamirShare[] = [];
  for (let i = 0; i < totalShares; i++) {
    shares.push({ index: i + 1, value: new Uint8Array(secret.length) });
  }

  // One polynomial per secret byte. Coefficient 0 is the secret byte;
  // 1..threshold-1 are random.
  const coeffs = new Uint8Array(threshold);
  const randomNeeded = (threshold - 1) * secret.length;
  const randomBuf = rand(randomNeeded);
  if (randomBuf.length < randomNeeded) {
    throw new Error("recovery: shamir random source returned too few bytes");
  }
  let randIdx = 0;

  for (let j = 0; j < secret.length; j++) {
    coeffs[0] = secret[j] ?? 0;
    for (let k = 1; k < threshold; k++) {
      coeffs[k] = randomBuf[randIdx++] ?? 0;
    }
    for (const share of shares) {
      share.value[j] = polyEval(coeffs, share.index);
    }
  }
  return shares;
}

/**
 * Reconstruct the secret from at least `threshold` shares per §5.4.
 * Each share's `value` MUST have the same length; that common length
 * is the recovered secret's length.
 *
 * Caller MUST track the threshold against the manifest. This function
 * does not enforce a minimum count; supplying more than threshold is
 * well-defined (Lagrange interpolation is exact for any subset >=
 * threshold), and supplying fewer yields a nonsense byte string with
 * no error.
 */
export function combineShares(shares: ShamirShare[]): Uint8Array {
  if (shares.length === 0) {
    throw new Error("recovery: combine got no shares");
  }
  const secretLen = shares[0]!.value.length;
  if (secretLen === 0) {
    throw new Error("recovery: combine got empty share value");
  }
  const xs = new Uint8Array(shares.length);
  const seen = new Set<number>();
  for (let i = 0; i < shares.length; i++) {
    const s = shares[i]!;
    if (s.index === 0) {
      throw new Error(`recovery: share[${i}] has invalid index 0`);
    }
    if (s.index < 0 || s.index > 255 || !Number.isInteger(s.index)) {
      throw new Error(`recovery: share[${i}] index ${s.index} out of [1, 255]`);
    }
    if (seen.has(s.index)) {
      throw new Error(
        `recovery: share index ${s.index} appears more than once`,
      );
    }
    seen.add(s.index);
    if (s.value.length !== secretLen) {
      throw new Error(
        `recovery: share[${i}] value length ${s.value.length} differs from share[0] length ${secretLen}`,
      );
    }
    xs[i] = s.index;
  }

  const out = new Uint8Array(secretLen);
  const ys = new Uint8Array(shares.length);
  for (let j = 0; j < secretLen; j++) {
    for (let i = 0; i < shares.length; i++) {
      ys[i] = shares[i]!.value[j] ?? 0;
    }
    out[j] = lagrangeInterpolateAtZero(xs, ys);
  }
  return out;
}

// ---------------------------------------------------------------------------
// GF(256) tables under AES reduction polynomial 0x11b, generator g = 3.

const gf256Exp = new Uint8Array(256);
const gf256Log = new Uint8Array(256);

(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    gf256Exp[i] = x;
    gf256Log[x] = i;
    x = gf256MulRaw(x, 3);
  }
  gf256Exp[255] = 1;
})();

function gf256MulRaw(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if ((b & 1) === 1) {
      p ^= a;
    }
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi !== 0) {
      a ^= 0x1b;
    }
    b >>= 1;
  }
  return p & 0xff;
}

function gf256Mul(a: number, b: number): number {
  if (a === 0 || b === 0) {
    return 0;
  }
  const idx = (gf256Log[a]! + gf256Log[b]!) % 255;
  return gf256Exp[idx]!;
}

function gf256Inv(a: number): number {
  if (a === 0) {
    throw new Error("recovery: gf256Inv(0)");
  }
  return gf256Exp[255 - gf256Log[a]!]!;
}

function polyEval(coeffs: Uint8Array, x: number): number {
  let y = 0;
  for (let k = coeffs.length - 1; k >= 0; k--) {
    y = gf256Mul(y, x) ^ (coeffs[k] ?? 0);
  }
  return y & 0xff;
}

function lagrangeInterpolateAtZero(xs: Uint8Array, ys: Uint8Array): number {
  let result = 0;
  for (let i = 0; i < xs.length; i++) {
    let num = 1;
    let den = 1;
    for (let k = 0; k < xs.length; k++) {
      if (k === i) {
        continue;
      }
      num = gf256Mul(num, xs[k]!);
      den = gf256Mul(den, xs[k]! ^ xs[i]!);
    }
    const basis = gf256Mul(num, gf256Inv(den));
    result ^= gf256Mul(ys[i]!, basis);
  }
  return result & 0xff;
}
