/**
 * Split an absolute URL into its lower-cased `scheme://authority` and the
 * untouched remainder (path, query).
 *
 * @param value - An absolute URL as written.
 * @returns The two parts, or `undefined` when there is no `://`.
 */
function splitAuthority(
  value: string,
): { authority: string; rest: string } | undefined {
  const start = value.indexOf("://")

  if (start === -1) return undefined

  const pathStart = value.indexOf("/", start + 3)
  const end = pathStart === -1 ? value.length : pathStart

  return {
    authority: value.slice(0, end).toLowerCase(),
    rest: value.slice(end),
  }
}

/**
 * Whether a `resource` parameter names the configured resource. Scheme and
 * host are compared case-insensitively (RFC 3986 § 6.2.2.1); the path and
 * query must match exactly.
 *
 * @param configured - The configured `resource` option.
 * @param given - The raw `resource` parameter, unvalidated.
 * @returns `true` when both name the same resource.
 * @internal
 */
export function sameResource(configured: string, given: string): boolean {
  if (given === configured) return true

  const a = splitAuthority(configured)
  const b = splitAuthority(given)

  return (
    a !== undefined &&
    b !== undefined &&
    a.authority === b.authority &&
    a.rest === b.rest
  )
}
