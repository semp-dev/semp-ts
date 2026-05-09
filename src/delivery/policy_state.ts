/**
 * Per-user authoritative policy view per DELIVERY.md §7.2.
 *
 * `applyPolicyMessage` takes a verified {@link UserPolicyMessage} and
 * either applies every operation atomically (advancing
 * `policy_version`) or rejects the whole message without mutating
 * state. Atomicity is the §7.2 guarantee: a single unrecognized kind
 * rejects the whole message; unrelated operations in the same
 * message MUST NOT be applied.
 *
 * Apply does NOT verify the signature on the message — callers MUST
 * run {@link verifyUserPolicyMessage} before invoking
 * {@link PolicyState.apply}.
 *
 * @module
 */

import {
  type PolicyOperation,
  type UserPolicyMessage,
  PolicyKindAcceptedSender,
  PolicyKindBlock,
  PolicyKindFirstContact,
  validateUserPolicyMessage,
} from "./user_policy.js";

/** §7.3 default rule kinds for v1.0.0. */
export function defaultPolicyKinds(): string[] {
  return [PolicyKindBlock, PolicyKindAcceptedSender, PolicyKindFirstContact];
}

/** Reason codes for policy apply failures (mirror ERRORS.md §5). */
export type PolicyApplyReasonCode =
  | "policy_kind_unsupported"
  | "policy_op_invalid"
  | "policy_version_stale";

/** Typed error wrapping a structured policy rejection. */
export class PolicyApplyError extends Error {
  override readonly name = "PolicyApplyError";
  constructor(
    public readonly code: PolicyApplyReasonCode,
    public readonly details: {
      kind?: string;
      opIndex?: number;
      submittedVersion?: number;
      currentVersion?: number;
      detail?: string;
    } = {},
  ) {
    super(messageFor(code, details));
  }
}

function messageFor(
  code: PolicyApplyReasonCode,
  d: { kind?: string; opIndex?: number; submittedVersion?: number; currentVersion?: number; detail?: string },
): string {
  switch (code) {
    case "policy_kind_unsupported":
      return `delivery: policy operation[${d.opIndex ?? 0}] kind ${JSON.stringify(d.kind ?? "")} is not supported`;
    case "policy_op_invalid":
      return d.detail !== undefined && d.detail !== ""
        ? `delivery: policy operation[${d.opIndex ?? 0}] is invalid: ${d.detail}`
        : `delivery: policy operation[${d.opIndex ?? 0}] is invalid`;
    case "policy_version_stale":
      return `delivery: submitted policy_version ${d.submittedVersion ?? 0} is not greater than current ${d.currentVersion ?? 0}`;
  }
}

/**
 * Snapshot of a {@link PolicyState} at one point in time. Used for
 * propagation to other devices on next connection per §7.2 and for
 * persistence checkpointing.
 */
export interface PolicySnapshot {
  user_id: string;
  policy_version: number;
  /** ISO 8601 UTC timestamp of the most recent applied message. */
  last_timestamp: string;
  /** Per-kind list-shaped entries, keyed by kind, then by entry_id. */
  list_entries: Record<string, Record<string, unknown>>;
  /** Per-kind singleton entries (e.g. semp.dev/first_contact). */
  singletons: Record<string, unknown>;
}

/**
 * Per-user policy state. Concurrency-safe within a single JS event
 * loop (no async mutation between read-modify-write).
 *
 * Does NOT enforce DELIVERY.md §7.5 encrypted-at-rest storage —
 * that is the persistence layer's responsibility.
 */
export class PolicyState {
  private readonly userIdValue: string;
  private readonly supportedKinds: Set<string>;

  private policyVersionValue = 0;
  private lastTimestampValue = "";

  private readonly listEntriesMap = new Map<string, Map<string, unknown>>();
  private readonly singletonsMap = new Map<string, unknown>();

  /**
   * @param userId - the account this state belongs to
   * @param kinds - rule kinds to register; defaults to {@link defaultPolicyKinds}
   */
  constructor(userId: string, kinds?: string[]) {
    if (userId === "") {
      throw new Error("delivery: policy state requires user_id");
    }
    const ks = kinds === undefined || kinds.length === 0 ? defaultPolicyKinds() : kinds;
    this.userIdValue = userId;
    this.supportedKinds = new Set();
    for (const k of ks) {
      if (k === "") {
        throw new Error("delivery: policy state cannot register empty kind");
      }
      this.supportedKinds.add(k);
    }
  }

  /** Account this state belongs to. */
  userId(): string {
    return this.userIdValue;
  }

  /** Current policy_version per §7.2. Zero before any message has been applied. */
  currentVersion(): number {
    return this.policyVersionValue;
  }

  /** Timestamp of the most recently applied message; `""` before any apply. */
  lastTimestamp(): string {
    return this.lastTimestampValue;
  }

  /** Whether `kind` is registered for this state. */
  supportsKind(kind: string): boolean {
    return this.supportedKinds.has(kind);
  }

  /** Registered kinds, lexically sorted. */
  registeredKinds(): string[] {
    return Array.from(this.supportedKinds.values()).sort();
  }

  /**
   * Apply `m` atomically per §7.2. On success advances
   * `policy_version` and applies every operation. On any per-message
   * failure throws a {@link PolicyApplyError} with structured
   * details and leaves state unchanged.
   *
   * Caller MUST have run {@link verifyUserPolicyMessage} first.
   */
  apply(m: UserPolicyMessage): void {
    try {
      validateUserPolicyMessage(m);
    } catch (err) {
      // Translate per-op validate failures into a typed
      // policy_op_invalid; structural failures propagate as-is.
      const probe = classifyOpInvalid(err instanceof Error ? err.message : String(err), m);
      if (probe !== null) {
        throw new PolicyApplyError("policy_op_invalid", {
          kind: probe.kind,
          opIndex: probe.opIndex,
          detail: probe.detail,
        });
      }
      throw err instanceof Error
        ? new Error(`delivery: policy validate: ${err.message}`)
        : new Error(`delivery: policy validate: ${String(err)}`);
    }
    if (m.user_id !== this.userIdValue) {
      throw new Error(
        `delivery: policy message user_id ${JSON.stringify(m.user_id)} does not match state user_id ${JSON.stringify(this.userIdValue)}`,
      );
    }

    // §7.2 ordering: monotonic policy_version with later-timestamp
    // tie-break for equal versions. A submission whose (version,
    // timestamp) is not strictly after the current state is stale.
    const submittedTime = Date.parse(m.timestamp);
    const lastTime =
      this.lastTimestampValue === ""
        ? -Infinity
        : Date.parse(this.lastTimestampValue);
    if (
      m.policy_version < this.policyVersionValue ||
      (m.policy_version === this.policyVersionValue && submittedTime <= lastTime)
    ) {
      throw new PolicyApplyError("policy_version_stale", {
        submittedVersion: m.policy_version,
        currentVersion: this.policyVersionValue,
      });
    }

    // Pre-flight every op for unsupported-kind before mutating —
    // §7.2 atomicity.
    for (let i = 0; i < m.operations.length; i++) {
      const op = m.operations[i]!;
      if (!this.supportedKinds.has(op.kind)) {
        throw new PolicyApplyError("policy_kind_unsupported", {
          kind: op.kind,
          opIndex: i,
        });
      }
    }

    // Apply.
    for (const op of m.operations) {
      this.applyOp(op);
    }
    this.policyVersionValue = m.policy_version;
    this.lastTimestampValue = m.timestamp;
  }

  private applyOp(op: PolicyOperation): void {
    if (op.kind === PolicyKindFirstContact) {
      // Singleton: modify is upsert; add/remove rejected upstream.
      this.singletonsMap.set(op.kind, deepClone(op.entry));
      return;
    }
    // List-shaped kinds.
    let bucket = this.listEntriesMap.get(op.kind);
    if (bucket === undefined) {
      bucket = new Map();
      this.listEntriesMap.set(op.kind, bucket);
    }
    if (op.op === "add" || op.op === "modify") {
      const id = entryIdFor(op);
      if (id === "") {
        // Skip silently rather than inserting under "" so callers
        // see the no-op rather than a corrupted bucket.
        return;
      }
      bucket.set(id, deepClone(op.entry));
      return;
    }
    if (op.op === "remove") {
      if (op.entry_id !== undefined && op.entry_id !== "") {
        bucket.delete(op.entry_id);
      }
      return;
    }
  }

  /** Deep copy of the entries currently held for `kind`, keyed by entry id. */
  listEntries(kind: string): Record<string, unknown> {
    const src = this.listEntriesMap.get(kind);
    const out: Record<string, unknown> = {};
    if (src === undefined) {
      return out;
    }
    for (const [id, v] of src) {
      out[id] = deepClone(v);
    }
    return out;
  }

  /**
   * Copy of the current singleton entry for `kind`, or `undefined`
   * if none has been set.
   */
  singleton(kind: string): unknown {
    if (!this.singletonsMap.has(kind)) {
      return undefined;
    }
    return deepClone(this.singletonsMap.get(kind));
  }

  /** Deep copy of all state for propagation / persistence. */
  snapshot(): PolicySnapshot {
    const list: Record<string, Record<string, unknown>> = {};
    for (const [kind, bucket] of this.listEntriesMap) {
      const inner: Record<string, unknown> = {};
      for (const [id, v] of bucket) {
        inner[id] = deepClone(v);
      }
      list[kind] = inner;
    }
    const singletons: Record<string, unknown> = {};
    for (const [kind, v] of this.singletonsMap) {
      singletons[kind] = deepClone(v);
    }
    return {
      user_id: this.userIdValue,
      policy_version: this.policyVersionValue,
      last_timestamp: this.lastTimestampValue,
      list_entries: list,
      singletons,
    };
  }
}

/**
 * Extract the entry id from a list-shaped op. For remove/modify the
 * op's own `entry_id` is authoritative; for add the spec puts the
 * id inside the entry payload (`id` field, ULID RECOMMENDED per
 * §7.3).
 */
function entryIdFor(op: PolicyOperation): string {
  if (op.entry_id !== undefined && op.entry_id !== "") {
    return op.entry_id;
  }
  if (
    typeof op.entry === "object" &&
    op.entry !== null &&
    "id" in (op.entry as Record<string, unknown>)
  ) {
    const id = (op.entry as Record<string, unknown>).id;
    if (typeof id === "string") {
      return id;
    }
  }
  return "";
}

/**
 * Heuristically map a `validateUserPolicyMessage` error to the
 * triple (op_index, kind, detail) when it originates from a §7.3
 * op-kind violation. Returns null for structural errors that are
 * not specific op-kind violations.
 *
 * The mapping leans on the validator's stable error-string format
 * (`delivery: user policy operations[N] ...`) — same approach as
 * the semp-go reference.
 */
function classifyOpInvalid(
  msg: string,
  m: UserPolicyMessage,
): { opIndex: number; kind: string; detail: string } | null {
  const prefix = "delivery: user policy operations[";
  if (!msg.startsWith(prefix)) {
    return null;
  }
  const rest = msg.slice(prefix.length);
  const end = rest.indexOf("]");
  if (end < 1) {
    return null;
  }
  const idxStr = rest.slice(0, end);
  if (!/^\d+$/.test(idxStr)) {
    return null;
  }
  const idx = Number(idxStr);
  if (idx < 0 || idx >= m.operations.length) {
    return null;
  }
  let detail = rest.slice(end + 1);
  if (detail.startsWith(" ")) {
    detail = detail.slice(1);
  }
  return { opIndex: idx, kind: m.operations[idx]!.kind, detail };
}

function deepClone<T>(v: T): T {
  if (v === undefined || v === null) {
    return v;
  }
  return JSON.parse(JSON.stringify(v)) as T;
}
