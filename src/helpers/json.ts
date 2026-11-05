/**
 * Serialise a hook's result to JSON, check its size, and return a fresh
 * deep copy, so the server never keeps a live object the hook still holds.
 *
 * @param value - Whatever the hook returned.
 * @param limit - Largest serialised size in UTF-8 bytes.
 * @param label - Name of the hook, for the error message.
 * @returns A JSON-safe copy, or `undefined` when `value` is `undefined`.
 * @throws {TypeError} When the value is not JSON-serializable or is larger
 *   than `limit` bytes.
 * @internal
 */
export function jsonCopy(
  value: unknown,
  limit: number,
  label: string,
): unknown {
  if (value === undefined) return undefined

  // `unknown`: JSON.stringify returns undefined for a function or symbol.
  let text: unknown

  try {
    text = JSON.stringify(value)
  } catch {
    throw new TypeError(`${label} returned data that is not JSON-serializable`)
  }

  if (typeof text !== "string") {
    throw new TypeError(`${label} returned data that is not JSON-serializable`)
  }

  if (Buffer.byteLength(text, "utf8") > limit) {
    throw new TypeError(`${label} returned more than ${limit} bytes`)
  }

  const copy: unknown = JSON.parse(text)

  return copy
}
