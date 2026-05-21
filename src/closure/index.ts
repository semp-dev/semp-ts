/**
 * Account closure layer per CLOSURE.md.
 *
 * Wire records (request + cancel) and signing primitives, plus
 * the home-server driver that orchestrates pending -> finalized
 * lifecycle on a {@link ClosureStore}.
 *
 * @module
 */

export {
  type ClosureRecord,
  type ClosureSignature,
  type SignClosureRecordInput,
  type SignClosureRecordResult,
  type Step,
  type ValidateClosureOptions,
  AccountClosurePrefix,
  MaxGracePeriodSeconds,
  MinGracePeriodSeconds,
  RecommendedGracePeriodSeconds,
  RecordType,
  RecordVersion,
  SignatureAlgorithmEd25519,
  finalizationAt,
  isFinalizable,
  signClosureRecord,
  validateClosureRecord,
  verifyClosureRecord,
} from "./closure.js";

export {
  type ClosureStore,
  AlreadyPendingError,
  InMemoryClosureStore,
  MinRetentionMs,
  RecommendedRetentionMs,
} from "./store.js";

export {
  type DriverConfig,
  type FinalizeResult,
  type RecipientPolicyFunc,
  type SubmitResult,
  Driver,
} from "./driver.js";
