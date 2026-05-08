/**
 * Real-server interop test: semp-ts client ↔ semp-go server.
 *
 * Builds and runs the cmd/semp-server binary from the sibling
 * `semp-go` checkout, dials it over WebSocket with semp-ts's
 * `runClient`, and asserts the four-message handshake completes and
 * a Session is produced with sane fields.
 *
 * Skips automatically when:
 *  - `go` is not on PATH
 *  - The semp-go directory is not reachable (set `SEMP_GO_DIR` to
 *    override the default `../semp-go` path)
 *  - The Go build fails (the binary version is stale or has a
 *    compile error)
 *
 * Drives `dialWS(allowInsecure: true)` because the demo server
 * listens on plain `ws://`. Uses the deterministic seed-derived
 * keys (semp-go's `internal/demoseed`) so the client knows the
 * expected `serverDomainPub` without a discovery round trip.
 *
 * @module
 */

import { spawn, type ChildProcess } from "node:child_process";
import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { sha256 } from "@noble/hashes/sha2.js";

import { dialWS } from "../../src/transport/index.js";
import { runClient } from "../../src/handshake/driver.js";
import { fingerprint, publicKeyFromSeed } from "../../src/keys/index.js";

const SEED = "semp-ts-interop-do-not-use-in-production";
const DOMAIN = "example.com";
const USER = "alice@example.com";

function deterministicIdentitySeed(seed: string, identity: string): Uint8Array {
  return sha256(new TextEncoder().encode(`identity:${seed}:${identity}`));
}

function deterministicDomainSigningSeed(seed: string, domain: string): Uint8Array {
  return sha256(new TextEncoder().encode(`domain-signing:${seed}:${domain}`));
}

function locateSempGo(): string | null {
  const env = process.env.SEMP_GO_DIR;
  if (env !== undefined && env !== "") {
    try {
      const stat = statSync(env);
      if (stat.isDirectory()) {
        return env;
      }
    } catch {
      return null;
    }
  }
  // Default: sibling checkout next to semp-ts.
  const sibling = resolve(__dirname, "..", "..", "..", "semp-go");
  try {
    const stat = statSync(sibling);
    if (stat.isDirectory()) {
      return sibling;
    }
  } catch {
    // not present
  }
  return null;
}

function haveGo(): boolean {
  try {
    execSync("go version", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function buildSempServer(sempGoDir: string, outDir: string): string {
  const binPath = join(outDir, "semp-server");
  execSync(`go build -o ${binPath} ./cmd/semp-server`, {
    cwd: sempGoDir,
    stdio: "pipe",
  });
  return binPath;
}

function pickPort(): number {
  // Random in the high ephemeral range to avoid collisions.
  return 40000 + Math.floor(Math.random() * 20000);
}

interface ServerHandle {
  proc: ChildProcess;
  port: number;
  ready: Promise<void>;
}

function startServer(binPath: string, port: number): ServerHandle {
  const proc = spawn(
    binPath,
    [
      `-addr=:${String(port)}`,
      `-domain=${DOMAIN}`,
      `-users=${USER}`,
      `-seed=${SEED}`,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  let resolveReady: () => void;
  let rejectReady: (err: Error) => void;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });

  let stderr = "";
  proc.stderr?.on("data", (chunk: Buffer) => {
    const text = chunk.toString("utf8");
    stderr += text;
    if (stderr.includes("listening on")) {
      resolveReady();
    }
  });
  proc.on("error", (err) => rejectReady(err));
  proc.on("exit", (code) => {
    if (code !== null && code !== 0) {
      rejectReady(new Error(`semp-server exited with code ${code}: ${stderr}`));
    }
  });
  // 5-second guard so we don't hang forever on a misbehaving binary.
  const guard = setTimeout(() => {
    rejectReady(new Error(`semp-server did not log "listening on" within 5s: ${stderr}`));
  }, 5_000);
  void ready.finally(() => clearTimeout(guard));

  return { proc, port, ready };
}

const sempGoDir = locateSempGo();
const goAvailable = haveGo();

const interopRunnable = sempGoDir !== null && goAvailable;

describe.skipIf(!interopRunnable)("interop: semp-ts client ↔ semp-go server", () => {
  let workDir: string;
  let server: ServerHandle | null = null;

  beforeAll(async () => {
    if (sempGoDir === null) {
      throw new Error("unreachable: skip should have engaged");
    }
    workDir = mkdtempSync(join(tmpdir(), "semp-interop-"));
    let binPath: string;
    try {
      binPath = buildSempServer(sempGoDir, workDir);
    } catch (err) {
      throw new Error(
        `go build failed for ${sempGoDir}/cmd/semp-server: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    // Verify it actually exists and is executable.
    readFileSync(binPath);
    const port = pickPort();
    server = startServer(binPath, port);
    await server.ready;
  }, 30_000);

  afterAll(async () => {
    if (server !== null) {
      server.proc.kill("SIGTERM");
      await new Promise<void>((resolve) => {
        server?.proc.once("exit", () => resolve());
        // Force-kill after 2s.
        setTimeout(() => {
          server?.proc.kill("SIGKILL");
          resolve();
        }, 2_000);
      });
    }
    if (workDir !== undefined) {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  test("runClient handshake against semp-go server", async () => {
    if (server === null) {
      throw new Error("server not started");
    }
    const url = `ws://127.0.0.1:${server.port}/v1/ws`;
    const transport = await dialWS(url, { allowInsecure: true });

    const serverSeed = deterministicDomainSigningSeed(SEED, DOMAIN);
    const serverDomainPub = publicKeyFromSeed(serverSeed);

    const identitySeed = deterministicIdentitySeed(SEED, USER);
    const identityPub = publicKeyFromSeed(identitySeed);
    const identityFp = fingerprint(identityPub);

    const session = await runClient(transport, {
      suite: "x25519-chacha20-poly1305",
      capabilities: {
        encryption_algorithms: ["x25519-chacha20-poly1305"],
        extensions: [],
      },
      transport: "ws",
      serverDomainPub,
      identity: {
        clientId: USER,
        clientIdentity: USER,
        longTermSeed: identitySeed,
        longTermKeyId: identityFp,
      },
    });

    // Successful handshake → Session is non-null with the expected role.
    expect(session.role).toBe("client");
    expect(session.sessionId.length).toBeGreaterThan(0);
    expect(session.sessionTTL).toBeGreaterThan(0);
    expect(session.keys.encC2S.length).toBe(32);
    expect(session.keys.envMAC.length).toBe(32);

    await session.close();
  }, 15_000);
});
