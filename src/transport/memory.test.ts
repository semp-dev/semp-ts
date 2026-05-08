import { describe, expect, test } from "vitest";

import { newPair } from "./memory.js";

describe("transport/memory", () => {
  test("send on one end receives on the other", async () => {
    const [a, b] = newPair();
    await a.send(new TextEncoder().encode("hello"));
    const got = await b.receive();
    expect(got).not.toBeNull();
    expect(new TextDecoder().decode(got!)).toBe("hello");
  });

  test("preserves message boundaries with multiple sends", async () => {
    const [a, b] = newPair();
    await a.send(new TextEncoder().encode("first"));
    await a.send(new TextEncoder().encode("second"));
    const m1 = await b.receive();
    const m2 = await b.receive();
    expect(new TextDecoder().decode(m1!)).toBe("first");
    expect(new TextDecoder().decode(m2!)).toBe("second");
  });

  test("receive resolves null after writer closes and queue drains", async () => {
    const [a, b] = newPair();
    await a.send(new TextEncoder().encode("queued"));
    await a.close();
    const queued = await b.receive();
    expect(new TextDecoder().decode(queued!)).toBe("queued");
    const eof = await b.receive();
    expect(eof).toBeNull();
  });

  test("waiting receiver wakes when writer pushes", async () => {
    const [a, b] = newPair();
    const recv = b.receive();
    await a.send(new TextEncoder().encode("delayed"));
    const got = await recv;
    expect(new TextDecoder().decode(got!)).toBe("delayed");
  });

  test("send after local close rejects", async () => {
    const [a] = newPair();
    await a.close();
    await expect(a.send(new TextEncoder().encode("late"))).rejects.toThrow();
  });
});
