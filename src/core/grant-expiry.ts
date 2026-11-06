import type { ResolvedOptions } from "../interfaces/options.js"
import type { GrantRecord } from "../interfaces/records.js"

type ExpiryOptions = Pick<ResolvedOptions, "grantTtlMs" | "grantIdleMs">

/**
 * When a new grant ends: `lifetimes.grant` after approval, or sooner when
 * `lifetimes.grantIdle` is shorter.
 *
 * @param options - The resolved grant lifetimes.
 * @param now - The approval time, in ms.
 * @returns The grant's first expiry, in ms.
 * @internal
 */
export function initialGrantExpiry(
  options: ExpiryOptions,
  now: number,
): number {
  const absolute = now + options.grantTtlMs

  return options.grantIdleMs > 0
    ? Math.min(absolute, now + options.grantIdleMs)
    : absolute
}

/**
 * The grant's new expiry after a refresh under `lifetimes.grantIdle`: the
 * idle window counted from now, never past the absolute limit.
 *
 * @param options - The resolved grant lifetimes.
 * @param grant - The grant being renewed.
 * @param now - The refresh time, in ms.
 * @returns The later expiry, or `undefined` when nothing moves.
 * @internal
 */
export function slidGrantExpiry(
  options: ExpiryOptions,
  grant: Pick<GrantRecord, "createdAt" | "expiresAt">,
  now: number,
): number | undefined {
  if (options.grantIdleMs <= 0) return undefined

  const next = Math.min(
    grant.createdAt + options.grantTtlMs,
    now + options.grantIdleMs,
  )

  return next > grant.expiresAt ? next : undefined
}
