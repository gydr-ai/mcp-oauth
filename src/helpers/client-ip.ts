import type { ResolvedOptions } from "../interfaces/options.js"

/**
 * The client address used as the rate-limit key: `getClientIp` when given,
 * else the right-most `X-Forwarded-For` entry when `trustProxy` is set, else
 * `"unknown"`. The right-most entry is the one the nearest proxy added; the
 * others are supplied by the client and can be forged.
 *
 * @param options - Checked options.
 * @param request - The request.
 * @returns The key.
 * @internal
 */
export function clientIp(
  options: Pick<ResolvedOptions, "getClientIp" | "trustProxy">,
  request: Request,
): string {
  const custom = options.getClientIp?.(request)

  if (custom !== undefined && custom !== "") return custom

  if (!options.trustProxy) return "unknown"

  const forwarded = request.headers.get("x-forwarded-for")
  const hops = (forwarded ?? "")
    .split(",")
    .map((hop) => hop.trim())
    .filter((hop) => hop !== "")

  return hops[hops.length - 1] ?? "unknown"
}
