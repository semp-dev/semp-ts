/**
 * In-process loopback transport. Two ends share a pair of FIFO
 * queues; whatever one peer sends, the other receives. Used by
 * tests that exercise the handshake driver, session machine, and
 * client/server orchestration without standing up a real
 * WebSocket / HTTP/2 server.
 *
 * NOT a transport for production traffic. The two peers run in
 * the same process and share memory; there is no encryption,
 * no flow control, no message-size enforcement.
 *
 * @module
 */

import type { Transport } from "./transport.js";

class Endpoint implements Transport {
  outbox: Queue<Uint8Array>;
  inbox: Queue<Uint8Array>;
  closed = false;

  constructor(outbox: Queue<Uint8Array>, inbox: Queue<Uint8Array>) {
    this.outbox = outbox;
    this.inbox = inbox;
  }

  send(message: Uint8Array): Promise<void> {
    if (this.closed) {
      return Promise.reject(new Error("memory transport: send after close"));
    }
    this.outbox.push(message);
    return Promise.resolve();
  }

  receive(): Promise<Uint8Array | null> {
    return this.inbox.shift();
  }

  close(): Promise<void> {
    if (this.closed) {
      return Promise.resolve();
    }
    this.closed = true;
    // Closing one end does NOT immediately drain the other side's
    // outbox — buffered messages from the closed peer are still
    // delivered before the inbox returns null.
    this.outbox.closeWriter();
    this.inbox.closeReader();
    return Promise.resolve();
  }
}

/**
 * One-element-at-a-time async queue with closeable writer +
 * closeable reader. Once the writer closes, queued items still
 * drain to readers, then `shift` returns null. Once the reader
 * closes, `shift` rejects on subsequent calls.
 */
class Queue<T> {
  private items: T[] = [];
  private waiters: Array<{
    resolve: (v: T | null) => void;
    reject: (e: Error) => void;
  }> = [];
  private writerClosed = false;
  private readerClosed = false;

  push(v: T): void {
    if (this.writerClosed) {
      throw new Error("memory transport: push after writer close");
    }
    const next = this.waiters.shift();
    if (next !== undefined) {
      next.resolve(v);
    } else {
      this.items.push(v);
    }
  }

  shift(): Promise<T | null> {
    if (this.readerClosed) {
      return Promise.reject(new Error("memory transport: receive after reader close"));
    }
    const buffered = this.items.shift();
    if (buffered !== undefined) {
      return Promise.resolve(buffered);
    }
    if (this.writerClosed) {
      return Promise.resolve(null);
    }
    return new Promise<T | null>((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  closeWriter(): void {
    this.writerClosed = true;
    if (this.items.length === 0) {
      const drained = this.waiters.splice(0);
      for (const w of drained) {
        w.resolve(null);
      }
    }
  }

  closeReader(): void {
    this.readerClosed = true;
    const drained = this.waiters.splice(0);
    for (const w of drained) {
      w.reject(new Error("memory transport: receiver closed"));
    }
  }
}

/**
 * Construct a connected pair of in-process transports. The two
 * returned ends communicate symmetrically: bytes sent on one are
 * receivable on the other.
 */
export function newPair(): [Transport, Transport] {
  const aToB = new Queue<Uint8Array>();
  const bToA = new Queue<Uint8Array>();
  const a = new Endpoint(aToB, bToA);
  const b = new Endpoint(bToA, aToB);
  return [a, b];
}
