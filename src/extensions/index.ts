/**
 * Extensions layer per EXTENSIONS.md.
 *
 * @module
 */

export {
  type Entry,
  type Layer,
  type Map,
  type RegistryEntry,
  KeyError,
  MaxKeyLength,
  NamespacePrefixCore,
  Registry,
  SizeError,
  UnsupportedError,
  maxBytesFor,
  validate,
  validateKey,
  validateSize,
} from "./limits.js";

export {
  type ValidationFailureCode,
  type ValidationFailureItem,
  type ValidationFailureRejection,
  DefinitionPathPrefix,
  newValidationFailureRejection,
} from "./validation_failure.js";
