/**
 * Freeze an object graph in place, recursively.
 *
 * @param value - A value produced by `structuredClone` (plain data only).
 * @returns The same value, now deeply frozen.
 */
function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value)

    for (const key of Reflect.ownKeys(value)) {
      deepFreeze(Reflect.get(value, key))
    }
  }

  return value
}

/**
 * A deeply frozen copy of plain data, handed to integrator hooks so that a
 * hook can read validated state but can never change what the server goes
 * on to use.
 *
 * @param value - Plain, structured-cloneable data (no functions, no `Request`).
 * @returns An independent, deeply frozen copy.
 * @internal
 */
export function frozenCopy<T>(value: T): T {
  return deepFreeze(structuredClone(value))
}

/**
 * Deeply freeze data that the server owns and shares with hooks or callers,
 * such as pre-registered client records.
 *
 * @param value - Plain data to freeze in place.
 * @returns The same value, deeply frozen.
 * @internal
 */
export function freezeDeep<T>(value: T): T {
  return deepFreeze(value)
}
