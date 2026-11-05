/**
 * Whether a value is a plain object (not `null`, not an array).
 *
 * @param value - Any value.
 * @returns `true` for an object record.
 * @internal
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/**
 * Whether a value is an array of strings.
 *
 * @param value - Any value.
 * @returns `true` for a string array.
 * @internal
 */
export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
}
