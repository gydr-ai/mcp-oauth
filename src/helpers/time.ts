/**
 * Whether something with this expiry has expired at `now`. Written so that a
 * non-finite value on either side (`NaN`, `undefined` coerced to a number)
 * counts as expired: a broken clock or record must never keep a token alive.
 *
 * @param expiresAt - Expiry in milliseconds since the epoch, as stored.
 * @param now - Current time in milliseconds since the epoch.
 * @returns `true` unless `expiresAt` is a number strictly greater than `now`.
 * @internal
 */
export function hasExpired(expiresAt: number, now: number): boolean {
  return !(
    Number.isFinite(expiresAt) &&
    Number.isFinite(now) &&
    expiresAt > now
  )
}

/**
 * Wrap a clock so that it can only return finite numbers. Anything else
 * throws, which fails the current request closed instead of silently
 * disabling every expiry check.
 *
 * @param clock - Returns milliseconds since the epoch, such as `Date.now`.
 * @returns A clock with the same values, or throwing for a non-finite one.
 * @internal
 */
export function checkedClock(clock: () => number): () => number {
  return () => {
    const value: unknown = clock()

    if (typeof value !== "number" || !Number.isFinite(value)) {
      throw new TypeError("The configured clock returned a non-finite time")
    }

    return value
  }
}
