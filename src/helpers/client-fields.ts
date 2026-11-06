import { CLIENT_ID_LENGTH_LIMIT } from "../constants/defaults.js"
import type { SupportedGrantType } from "../interfaces/records.js"
import { isStringArray } from "./guards.js"
import { hasHiddenCharacters } from "./text.js"

/**
 * Does this `client_id` point at a Client ID Metadata Document? It must be an
 * `https` URL with a non-root path and no credentials or fragment, written in
 * exactly the form a URL parser would print it (so the identifier and the
 * address that is fetched can never differ: no dot segments, no case or
 * percent-encoding variants).
 *
 * @param clientId - The raw `client_id` parameter, unvalidated.
 * @returns `true` for a metadata-document client id.
 * @internal
 */
export function isMetadataDocumentClientId(clientId: string): boolean {
  if (
    clientId.length > CLIENT_ID_LENGTH_LIMIT ||
    !clientId.startsWith("https://") ||
    clientId.includes("#")
  ) {
    return false
  }

  let parsed: URL

  try {
    parsed = new URL(clientId)
  } catch {
    return false
  }

  return (
    parsed.hostname !== "" &&
    parsed.username === "" &&
    parsed.password === "" &&
    parsed.pathname.length > 1 &&
    parsed.href === clientId
  )
}

/**
 * A self-declared client name, trimmed, or `undefined` when it is empty,
 * longer than `maxLength`, or contains invisible or control characters.
 *
 * @param value - The raw `client_name` from registration metadata or a metadata document, of unknown type.
 * @param maxLength - Longest name accepted after trimming, in UTF-16 code units (`limits.clientNameLength`).
 * @returns The cleaned name, or `undefined`.
 * @internal
 */
export function cleanClientName(
  value: unknown,
  maxLength: number,
): string | undefined {
  if (typeof value !== "string") return undefined

  const name = value.trim()

  if (name.length === 0 || name.length > maxLength) return undefined

  return hasHiddenCharacters(name) ? undefined : name
}

/**
 * Whether a grant type is one this server issues.
 *
 * @param value - A grant type name.
 * @returns `true` for `authorization_code` or `refresh_token`.
 */
function isSupportedGrantType(value: string): value is SupportedGrantType {
  return value === "authorization_code" || value === "refresh_token"
}

/**
 * Interpret registered `grant_types`. Absent means `omitted` (by default
 * `authorization_code` alone, RFC 7591 § 2). The list must contain `authorization_code`; with `strict`,
 * any type this server cannot issue makes it invalid, otherwise such types
 * are dropped. Returns `undefined` when invalid.
 *
 * @param value - The raw `grant_types` metadata value, of unknown type; `undefined` means omitted.
 * @param strict - `true` for registration (any unknown grant type refuses), `false` for metadata documents (unknown types are dropped).
 * @param omitted - The grant types used when `value` is absent (`defaultGrantTypes`).
 * @returns The grant types, or `undefined` when invalid.
 * @internal
 */
export function parseGrantTypes(
  value: unknown,
  strict: boolean,
  omitted: readonly SupportedGrantType[] = ["authorization_code"],
): SupportedGrantType[] | undefined {
  if (value === undefined) return [...omitted]

  if (!isStringArray(value) || !value.includes("authorization_code")) {
    return undefined
  }

  const known = value.filter(isSupportedGrantType)

  if (strict && known.length !== value.length) return undefined

  return [...new Set(known)]
}

/**
 * Interpret a registered `scope` string against the supported scopes.
 * `null`: none registered. `undefined`: invalid (not a string, too long,
 * nothing supported, or — with `strict` — anything unsupported).
 *
 * @param value - The raw `scope` metadata value, of unknown type; `undefined` means omitted.
 * @param supported - The server's supported scopes.
 * @param strict - `true` for registration (an unsupported scope refuses), `false` for metadata documents (unsupported scopes are dropped).
 * @param maxLength - Longest `scope` string accepted (`limits.scopeLength`).
 * @returns The scopes, `null` when none were registered, or `undefined` when invalid.
 * @internal
 */
export function parseClientScopes(
  value: unknown,
  supported: readonly string[],
  strict: boolean,
  maxLength: number,
): string[] | undefined | null {
  if (value === undefined) return null

  if (typeof value !== "string" || value.length > maxLength) return undefined

  const requested = [...new Set(value.split(" ").filter((s) => s.length > 0))]
  const usable = requested.filter((s) => supported.includes(s))

  if (usable.length === 0) return undefined

  if (strict && usable.length < requested.length) return undefined

  return usable
}
