/**
 * Delivery layer per DELIVERY.md.
 *
 * Signed delivery receipts (§1.1.1), per-attempt acknowledgment
 * envelope (§1.1.1.5 / §1.6) including recipient-status visibility
 * (§1.6.4), retry-schedule primitives (§2.3), queue state record
 * (§2.5), and the per-user block list (§4) with match precedence.
 *
 * @module
 */

export {
  type DeliveryReceipt,
  type EnvelopeHash,
  type ReceiptSignature,
  type SignDeliveryReceiptInput,
  type SignDeliveryReceiptResult,
  type VerifyDeliveryReceiptInput,
  DeliveryReceiptPrefix,
  DeliveryReceiptType,
  DeliveryReceiptVersion,
  EnvelopeHashAlgorithmSHA256,
  ReceiptClockSkewToleranceSeconds,
  ReceiptSignatureAlgorithmEd25519,
  computeEnvelopeHash,
  signDeliveryReceipt,
  validateReceipt,
  verifyDeliveryReceipt,
  verifyEnvelopeBinding,
} from "./receipt.js";

export {
  type ReceiptStore,
  DefaultReceiptRetentionMs,
  InMemoryReceiptStore,
} from "./receipt_store.js";

export {
  type Acknowledgment,
  type DeliveryAck,
  type RecipientState,
  type RecipientStatus,
  type SenderIdentity,
  type Visibility,
  type VisibilityEntry,
  type VisibilityMode,
  MaxStatusMessageBytes,
  buildDeliveredAck,
  buildRejectedAck,
  matchVisibility,
  validateRecipientStatus,
} from "./ack.js";

export {
  type EffectiveRetryConfig,
  type RetryConfig,
  DefaultMaxRetryHorizonMs,
  MaxRetryHorizonCapMs,
  MaxRetryIntervalMs,
  MinJitterFloorMs,
  MinRetryAttempts,
  MinRetryInitialIntervalMs,
  MinRetryJitterFraction,
  MinRetryMultiplier,
  baseIntervalMs,
  effectiveDeadline,
  isRecoverableReason,
  jitterIntervalMs,
  nextAttemptAt,
  sanitizeRetry,
} from "./retry.js";

export {
  type QueueRecordState,
  type QueueState,
  isTerminalState,
  setTerminal,
} from "./queue.js";

export {
  type BlockEntry,
  type BlockList,
  type BlockListLookup,
  type BlockListSender,
  type BlocklistEntity,
  type BlocklistEntityType,
  type BlocklistScope,
  StaticBlockListLookup,
  matchBlockList,
} from "./blocklist.js";

export {
  type SubmissionEvent,
  type SubmissionResponse,
  type SubmissionResult,
  type SubmissionStep,
  SubmissionType,
  SubmissionVersion,
  newSubmissionEvent,
  newSubmissionResponse,
} from "./submission.js";

export {
  type CancelRequest,
  type CancelResponse,
  type CancelResult,
  newCancelRequest,
  newCancelResponse,
} from "./cancel.js";

export {
  type FetchRequest,
  type FetchResponse,
  type FetchStep,
  FetchType,
  FetchVersion,
  newFetchRequest,
  newFetchResponse,
} from "./fetch.js";

export {
  DefaultMaxQueueDepth,
  Inbox,
} from "./inbox.js";

export {
  type InternalRoute,
  type InternalRouteAck,
  InternalRouteTimeoutMs,
  InternalRouteType,
  InternalRouteVersion,
} from "./internalroute.js";

export {
  type Disposition,
  type DispositionDecision,
  type StagedHeld,
  type StagedHeldStage,
  type StageOutcome,
  DefaultStageTimeoutMs,
  DispositionKind,
  DispositionReasonAccepted,
  DispositionReasonOther,
  DispositionReasonPolicy,
  DispositionReasonSpam,
  aggregateDispositions,
  isStageComplete,
  validateDisposition,
} from "./disposition.js";

export {
  type SyncMessage,
  type SyncOp,
  type SyncOperation,
  type SyncSignatureBlock,
  SyncMessagePrefix,
  SyncMessageType,
  SyncMessageVersion,
  SyncStep,
  signSyncMessage,
  validateSyncMessage,
  verifySyncMessage,
} from "./sync.js";

export {
  type PolicyOp,
  type PolicyOperation,
  type UserPolicyMessage,
  type UserPolicySignatureBlock,
  PolicyKindAcceptedSender,
  PolicyKindBlock,
  PolicyKindFirstContact,
  UserPolicyPrefix,
  UserPolicyStep,
  UserPolicyType,
  UserPolicyVersion,
  signUserPolicyMessage,
  validateUserPolicyMessage,
  verifyUserPolicyMessage,
} from "./user_policy.js";

export {
  type CertificateProvider,
  type PartitionInput,
  partitionStages,
} from "./stage_partition.js";

export {
  type PolicyApplyReasonCode,
  type PolicySnapshot,
  PolicyApplyError,
  PolicyState,
  defaultPolicyKinds,
} from "./policy_state.js";

export {
  type DecodedBrief,
  type DomainKeyLookup,
  type DomainPolicyFunc,
  type EnvMACFunc,
  type InboxStore,
  type LocalAddressFunc,
  type PipelineConfig,
  type PipelineLogger,
  type PipelineRejection,
  type PipelineResult,
  type RecipientPolicyFunc,
  type SessionRetiredFunc,
  Pipeline,
} from "./pipeline.js";

export {
  type StageCompleteFunc,
  type StageDeliverFunc,
  type StageSuppressFunc,
  type StagedRunnerConfig,
  EnvelopeAlreadyHeldError,
  EnvelopeNotHeldError,
  StagedRunner,
} from "./staged_runner.js";

export {
  type AttemptResult,
  type DeliverFunc,
  type EventSink,
  type SchedulerConfig,
  type SchedulerStore,
  InMemorySchedulerStore,
  Scheduler,
  TickInProgressError,
  UnknownRecordError,
} from "./scheduler.js";

export {
  type Dialer,
  type EndpointResolver,
  type ForwarderConfig,
  type PeerDomainKeyLookup,
  Forwarder,
} from "./forwarder.js";

export {
  PersistentSilentCounter,
  PersistentSilentDefaults,
} from "./persistent_silent.js";

export {
  type StatusMessage,
  type StatusMessageSignature,
  type StatusState,
  type StatusVisibility,
  type StatusVisibilityEntry,
  type StatusVisibilityMode,
  StatusMessagePrefix,
  StatusMessageType,
  StatusMessageVersion,
  signStatusMessage,
  validateStatusMessage,
  verifyStatusMessage,
} from "./status_message.js";

export {
  UpgradeCapabilityPresent,
  UpgradeHeaderAddress,
  UpgradeHeaderCapability,
  UpgradeHeaderDomain,
  UpgradeHeaderIdentity,
} from "./upgrade_signal.js";

export {
  type DeviceSyncMarkerData,
  DeviceSyncExtensionID,
} from "./device_sync.js";
