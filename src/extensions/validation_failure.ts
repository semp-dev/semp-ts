/**
 * Canonical URL path prefix at which an extension's definition
 * document is published per EXTENSIONS.md §3.5 and RFC 8615. The
 * full URL is
 *   "https://<host>" + DefinitionPathPrefix + "<name>.json"
 * where <name> is the namespace-prefixed identifier such as
 * "semp.dev/foo" or "vendor.example.com/feature1".
 */
export const DefinitionPathPrefix = "/.well-known/semp-extensions/";

/**
 * Extension validation failure reporting per EXTENSIONS.md §3.9.3.
 *
 * Runtime validation failures across one or more extensions in an
 * envelope are reported with the `extension_unsupported` reason
 * code and an `errors` array carrying per-extension diagnostics.
 * Implementations MAY stop at the first failure and report a
 * single-entry array or continue and report all failures.
 *
 * @module
 */

/** Defined validation_failure diagnostics per §3.9.3 table. */
export type ValidationFailureCode =
  | "definition_unfetchable"
  | "definition_signature_invalid"
  | "data_schema_mismatch"
  | "placement_violation"
  | "authority_violation"
  | "dependency_unsatisfied"
  | "conflict_present";

/** Single entry in the §3.9.3 `errors` array. */
export interface ValidationFailureItem {
  extension: string;
  validation_failure: ValidationFailureCode;
}

/**
 * Envelope-rejection wire shape carrying one or more extension
 * validation failures. The reason_code is always
 * `extension_unsupported`; per-rule diagnostics live in
 * `errors[i].validation_failure`.
 */
export interface ValidationFailureRejection {
  type: "SEMP_ENVELOPE";
  step: "rejected";
  version: string;
  reason_code: "extension_unsupported";
  reason: string;
  errors: ValidationFailureItem[];
}

/**
 * Wrap one or more validation failures in the §3.9.3 envelope
 * rejection. The reason defaults to "Extension validation failed"
 * when omitted.
 */
export function newValidationFailureRejection(
  items: ValidationFailureItem[],
  reason = "Extension validation failed",
): ValidationFailureRejection {
  return {
    type: "SEMP_ENVELOPE",
    step: "rejected",
    version: "1.0.0",
    reason_code: "extension_unsupported",
    reason,
    errors: items,
  };
}
