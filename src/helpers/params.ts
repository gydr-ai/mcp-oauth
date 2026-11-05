/**
 * Parameters grouped by name, each with all its values in order.
 *
 * @internal
 */
export type Params = ReadonlyMap<string, readonly string[]>

/**
 * Group URL-encoded parameters by name, keeping repeated values.
 *
 * @param search - Parsed query or form body.
 * @returns The grouped parameters.
 * @internal
 */
export function groupParams(search: URLSearchParams): Params {
  const params = new Map<string, string[]>()

  for (const [key, value] of search) {
    const values = params.get(key)

    if (values) values.push(value)
    else params.set(key, [value])
  }

  return params
}

/**
 * Names that appear more than once, which RFC 6749 § 3.1 and § 3.2 forbid.
 *
 * @param params - Grouped parameters.
 * @returns The repeated names.
 * @internal
 */
export function duplicatedNames(params: Params): string[] {
  return [...params].filter(([, values]) => values.length > 1).map(([k]) => k)
}

/**
 * The value of a parameter; an empty value counts as absent.
 *
 * @param params - Grouped parameters.
 * @param name - Parameter name.
 * @returns The first value, or `undefined`.
 * @internal
 */
export function single(params: Params, name: string): string | undefined {
  const value = params.get(name)?.[0]

  return value === undefined || value === "" ? undefined : value
}

/**
 * Which of the parameters a protocol defines appear more than once. RFC 6749
 * § 3.1 and § 3.2 (OAuth 2.1 § 3.1) forbid repeating a defined parameter but
 * require unknown parameters to be ignored, even when repeated.
 *
 * @param params - Grouped query or form parameters, unvalidated.
 * @param defined - Names the endpoint defines.
 * @returns The defined names that were sent more than once.
 * @internal
 */
export function repeatedDefined(
  params: Params,
  defined: readonly string[],
): string[] {
  return defined.filter((name) => (params.get(name)?.length ?? 0) > 1)
}
