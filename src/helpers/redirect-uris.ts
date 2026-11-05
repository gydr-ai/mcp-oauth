/**
 * Which redirect URIs a client may use, and when a requested one counts as
 * registered. Authorization codes are delivered to these addresses, so the
 * rules are deliberately narrow:
 *
 * - allowed: `https` with a host, or plain `http` to a loopback host
 *   (`127.0.0.1`, `[::1]`, `localhost`) for native apps (RFC 8252 § 7.3);
 *   never a fragment (RFC 6749 § 3.1.2), never embedded credentials;
 * - comparison is character-for-character, except that a loopback URI may
 *   name any port, because native apps bind an ephemeral one.
 */

import { LOOPBACK_HOSTS } from "../constants/protocol.js"

/**
 * Default for {@link redirectUriProblem}'s length limit.
 *
 * @internal
 */
export const DEFAULT_REDIRECT_URI_LENGTH = 2048

/**
 * Why a redirect URI is not allowed.
 *
 * @internal
 */
export type RedirectUriProblem =
  | "unparseable"
  | "over_length"
  | "has_fragment"
  | "has_credentials"
  | "disallowed_scheme"
  | "reserved_query_parameter"

/**
 * Parameters the server adds to the redirect; a registered URI may not
 * carry them already, or the client could read a forged value (RFC 9700
 * § 4.1.1, OAuth 2.1 § 7.5.4.1, RFC 9207).
 */
const RESERVED_REDIRECT_PARAMETERS: readonly string[] = [
  "code",
  "state",
  "iss",
  "error",
  "error_description",
  "error_uri",
]

function tryParse(text: string): URL | undefined {
  try {
    return new URL(text)
  } catch {
    return undefined
  }
}

function isLoopbackHttp(url: URL): boolean {
  return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)
}

/**
 * True for a plain-`http` loopback URI.
 *
 * @param uri - A redirect URI, possibly unparseable.
 * @returns `true` for a loopback URI.
 * @internal
 */
export function isLoopbackRedirectUri(uri: string): boolean {
  const url = tryParse(uri)

  return url !== undefined && isLoopbackHttp(url)
}

/**
 * The reason `uri` is unusable for redirection, or `undefined` when usable.
 *
 * @param uri - A redirect URI from registration, a metadata document or configuration, unvalidated.
 * @param limits - Length limit to apply. Default: 2048 characters.
 * @param limits.redirectUriLength - Longest URI accepted, in characters (`limits.redirectUriLength`).
 * @returns The problem, or `undefined` when the URI is usable.
 * @internal
 */
export function redirectUriProblem(
  uri: string,
  limits: { readonly redirectUriLength: number } = {
    redirectUriLength: DEFAULT_REDIRECT_URI_LENGTH,
  },
): RedirectUriProblem | undefined {
  if (uri.length > limits.redirectUriLength) return "over_length"

  const url = tryParse(uri)

  if (url === undefined) return "unparseable"

  // Checked on the raw text: the parser forgets an empty fragment.
  if (uri.includes("#")) return "has_fragment"

  if (url.username.length > 0 || url.password.length > 0) {
    return "has_credentials"
  }

  const secure = url.protocol === "https:" && url.hostname.length > 0

  if (!secure && !isLoopbackHttp(url)) return "disallowed_scheme"

  return RESERVED_REDIRECT_PARAMETERS.some((name) => url.searchParams.has(name))
    ? "reserved_query_parameter"
    : undefined
}

/**
 * True when `uri` is allowed as a redirect URI.
 *
 * @param uri - A redirect URI, unvalidated.
 * @param limits - Length limit to apply. Default: 2048 characters.
 * @param limits.redirectUriLength - Longest URI accepted, in characters.
 * @returns `true` when usable.
 * @internal
 */
export function isAcceptableRedirectUri(
  uri: string,
  limits?: { readonly redirectUriLength: number },
): boolean {
  return redirectUriProblem(uri, limits) === undefined
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57
}

/**
 * `uri` with the `:port` after a loopback host removed, host lower-cased.
 *
 * @param uri - The raw URI text, exactly as registered or requested.
 * @param url - The same URI parsed; only its scheme and hostname are used.
 * @returns The URI without its port.
 */
function portless(uri: string, url: URL): string {
  const head = `${url.protocol}//${url.hostname}`

  if (uri.slice(0, head.length).toLowerCase() !== head.toLowerCase()) {
    return uri
  }

  let tail = uri.slice(head.length)

  if (tail.startsWith(":")) {
    let i = 1

    while (i < tail.length && isDigit(tail.charCodeAt(i))) i += 1
    tail = tail.slice(i)
  }

  return head.toLowerCase() + tail
}

/**
 * Is `requested` the same redirect URI as the registered one?
 *
 * @param registered - A redirect URI stored on the client, already validated.
 * @param requested - The raw `redirect_uri` query value, unvalidated.
 * @param limits - Length limit for the requested URI. Default: 2048 characters.
 * @param limits.redirectUriLength - Longest URI accepted, in characters.
 * @returns `true` on a match.
 * @internal
 */
export function redirectUriMatches(
  registered: string,
  requested: string,
  limits?: { readonly redirectUriLength: number },
): boolean {
  if (!isAcceptableRedirectUri(requested, limits)) return false

  if (requested === registered) return true

  const a = tryParse(registered)
  const b = tryParse(requested)

  if (a === undefined || b === undefined) return false

  if (!isLoopbackHttp(a) || !isLoopbackHttp(b)) return false

  // Compare the text, not parsed fields: parsing normalizes paths, and a
  // normalized match is not an exact one.
  return portless(registered, a) === portless(requested, b)
}

/**
 * Does `requested` match one of the registered URIs?
 *
 * @param registered - Redirect URIs stored on the client.
 * @param requested - The raw `redirect_uri` query value, unvalidated.
 * @param limits - Length limit for the requested URI. Default: 2048 characters.
 * @param limits.redirectUriLength - Longest URI accepted, in characters.
 * @returns `true` on a match.
 * @internal
 */
export function matchesAnyRedirectUri(
  registered: readonly string[],
  requested: string,
  limits?: { readonly redirectUriLength: number },
): boolean {
  return registered.some((uri) => redirectUriMatches(uri, requested, limits))
}

/**
 * Host to show a person: loopback without its port, otherwise `host`.
 *
 * @param uri - A redirect URI already matched against the client's registration.
 * @returns The host, or an empty string.
 * @internal
 */
export function redirectHostOf(uri: string): string {
  const url = tryParse(uri)

  if (url === undefined) return ""

  return isLoopbackHttp(url) ? url.hostname : url.host
}

/**
 * `scheme://host[:port]` of a URI, or `undefined`.
 *
 * @param uri - A redirect URI already matched against the client's registration.
 * @returns The origin, or `undefined`.
 * @internal
 */
export function originOf(uri: string): string | undefined {
  return tryParse(uri)?.origin
}

/**
 * Add response parameters to a redirect URI that has already been matched,
 * keeping any query it has. `undefined` values are left out.
 *
 * @param redirectUri - A redirect URI already matched against the client's registration; never pass an unchecked value.
 * @param params - Query parameters to append (`code`, `state`, `iss`, `error`…); `undefined` values are skipped.
 * @returns The redirect URL.
 * @internal
 */
export function buildRedirect(
  redirectUri: string,
  params: Readonly<Record<string, string | undefined>>,
): string {
  const target = new URL(redirectUri)

  for (const [name, value] of Object.entries(params)) {
    if (value !== undefined) target.searchParams.append(name, value)
  }

  return target.toString()
}
