/**
 * Helpers for placing / reading large-attachment items inside an
 * enclosure's `extensions` map per ATTACHMENTS.md §2.1.
 *
 * The wire shape under the enclosure is:
 *
 * ```json
 * {
 *   "extensions": {
 *     "semp.dev/large-attachment": { "data": { "items": [ ... ] } }
 *   }
 * }
 * ```
 *
 * @module
 */

import { type ExtensionData, type Item, ExtensionKey } from "./types.js";

/**
 * Read the array of items from the extensions map. Returns an
 * empty array when the extension is absent. Throws when the
 * entry is present but malformed.
 */
export function readFromExtensions(
  extensions: Record<string, unknown> | undefined,
): Item[] {
  if (extensions === undefined) {
    return [];
  }
  const entry = extensions[ExtensionKey];
  if (entry === undefined) {
    return [];
  }
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new Error(
      `largeattachment: extensions[${JSON.stringify(ExtensionKey)}] is not an object`,
    );
  }
  const data = (entry as Record<string, unknown>).data;
  if (data === undefined) {
    return [];
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("largeattachment: extension data is not an object");
  }
  const items = (data as Record<string, unknown>).items;
  if (items === undefined) {
    return [];
  }
  if (!Array.isArray(items)) {
    throw new Error("largeattachment: extension data.items is not an array");
  }
  for (let i = 0; i < items.length; i++) {
    if (typeof items[i] !== "object" || items[i] === null || Array.isArray(items[i])) {
      throw new Error(`largeattachment: extension data.items[${i}] is not an object`);
    }
  }
  return items as Item[];
}

/**
 * Append `newItems` to the existing items list under the
 * `semp.dev/large-attachment` extension. Returns a NEW extensions
 * map (input not mutated). Use when the caller may already have
 * other items in the list.
 */
export function appendToExtensions(
  extensions: Record<string, unknown> | undefined,
  newItems: Item[],
): Record<string, unknown> {
  const existing = readFromExtensions(extensions);
  return setOnExtensions(extensions, [...existing, ...newItems]);
}

/**
 * Replace the entire items list under the
 * `semp.dev/large-attachment` extension. Returns a NEW extensions
 * map (input not mutated). When `items` is empty, removes the
 * extension entirely.
 */
export function setOnExtensions(
  extensions: Record<string, unknown> | undefined,
  items: Item[],
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(extensions ?? {}) };
  if (items.length === 0) {
    delete out[ExtensionKey];
    return out;
  }
  const data: ExtensionData = { items };
  out[ExtensionKey] = { data };
  return out;
}

/**
 * Remove the `semp.dev/large-attachment` extension entry, if any.
 * Returns a NEW extensions map (input not mutated).
 */
export function removeFromExtensions(
  extensions: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(extensions ?? {}) };
  delete out[ExtensionKey];
  return out;
}

/**
 * Look up an item by its `id`. Returns the item or `null` when not
 * found. Throws if the extension entry is structurally malformed.
 */
export function findById(
  extensions: Record<string, unknown> | undefined,
  id: string,
): Item | null {
  for (const item of readFromExtensions(extensions)) {
    if (item.id === id) {
      return item;
    }
  }
  return null;
}
