import { DEFAULT_LIMITS } from "../constants/defaults.js"
import { LOOPBACK_HOSTS } from "../constants/protocol.js"
import { McpAuthConfigError } from "../errors/mcp-auth-config-error.js"
import type { Limits, RoutePaths } from "../interfaces/options.js"

/**
 * Parse and check the issuer or resource URL.
 *
 * @param name - Option name, for error messages.
 * @param value - The configured URL.
 * @param allowInsecureLocalhost - Whether plain `http` on loopback is allowed.
 * @returns The parsed URL, known to be `https` (or loopback `http` when allowed) without query, fragment or credentials.
 * @throws {McpAuthConfigError} When the URL is not absolute, carries a query,
 *   fragment or credentials, or is not `https`.
 * @internal
 */
export function parseServerUrl(
  name: string,
  value: string,
  allowInsecureLocalhost: boolean,
): URL {
  let url: URL

  try {
    url = new URL(value)
  } catch {
    throw new McpAuthConfigError(`${name} must be an absolute URL`)
  }

  if (value.includes("#") || url.search !== "" || value.includes("?")) {
    throw new McpAuthConfigError(`${name} must have no query or fragment`)
  }

  if (url.username !== "" || url.password !== "") {
    throw new McpAuthConfigError(`${name} must have no userinfo`)
  }

  const local = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)

  if (url.protocol !== "https:" && !(local && allowInsecureLocalhost)) {
    throw new McpAuthConfigError(
      `${name} must use https (http is allowed only for localhost with allowInsecureLocalhost)`,
    )
  }

  return url
}

/**
 * Remove trailing slashes: `/a/b/` becomes `/a/b`, `/` becomes the empty string.
 *
 * @param pathname - A URL path.
 * @returns The path without trailing slashes.
 * @internal
 */
export function trimPath(pathname: string): string {
  return pathname.replace(/\/+$/, "")
}

/**
 * Turn a lifetime in seconds into milliseconds, checking it.
 *
 * @param name - Lifetime name, for error messages.
 * @param value - Configured seconds, if any.
 * @param fallback - Default seconds.
 * @param min - Smallest allowed value, in seconds.
 * @param max - Largest allowed value, in seconds.
 * @returns The lifetime in milliseconds.
 * @throws {McpAuthConfigError} When the value is not an integer from `min` to `max`.
 * @internal
 */
export function seconds(
  name: string,
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  const chosen = value ?? fallback

  if (!Number.isInteger(chosen) || chosen < min || chosen > max) {
    throw new McpAuthConfigError(
      `lifetimes.${name} must be an integer from ${min} to ${max}`,
    )
  }

  return chosen * 1000
}

/**
 * Check one size or count limit.
 *
 * @param name - Limit name, for error messages.
 * @param value - Configured value, if any.
 * @param fallback - Default value.
 * @returns The limit.
 * @throws {McpAuthConfigError} When the value is not a positive integer.
 * @internal
 */
export function positive(
  name: string,
  value: number | undefined,
  fallback: number,
): number {
  const chosen = value ?? fallback

  if (!Number.isInteger(chosen) || chosen < 1) {
    throw new McpAuthConfigError(`limits.${name} must be a positive integer`)
  }

  return chosen
}

/**
 * Apply defaults to every limit.
 *
 * @param limits - Configured limits.
 * @returns Every limit, checked.
 * @throws {McpAuthConfigError} When a limit is not a positive integer.
 * @internal
 */
export function resolveLimits(limits: Limits = {}): Required<Limits> {
  const pick = (key: keyof Limits): number =>
    positive(key, limits[key], DEFAULT_LIMITS[key])

  return {
    clientNameLength: pick("clientNameLength"),
    redirectUris: pick("redirectUris"),
    redirectUriLength: pick("redirectUriLength"),
    stateLength: pick("stateLength"),
    scopeLength: pick("scopeLength"),
    registrationBytes: pick("registrationBytes"),
    formBytes: pick("formBytes"),
    clientMetadataBytes: pick("clientMetadataBytes"),
    clientMetadataTimeoutMs: pick("clientMetadataTimeoutMs"),
    clientMetadataFailures: pick("clientMetadataFailures"),
    grantContextBytes: pick("grantContextBytes"),
    consentDetailsBytes: pick("consentDetailsBytes"),
    grantDataBytes: pick("grantDataBytes"),
  }
}

/**
 * Check one endpoint path.
 *
 * @param name - Path name, for error messages.
 * @param path - The configured path.
 * @returns The path.
 * @throws {McpAuthConfigError} When it does not start with exactly one `/`,
 *   or contains `//`, a backslash, `?`, `#`, a dot segment or whitespace.
 * @internal
 */
export function checkPath(name: string, path: string): string {
  // `//host/x` and `\\host\x` are protocol-relative on many stacks; a path
  // must be unambiguous wherever it is echoed or compared.
  const segments = path.split("/").slice(1)

  if (
    !path.startsWith("/") ||
    path.includes("//") ||
    /[\\?#\s]/.test(path) ||
    segments.some((segment) => segment === "." || segment === "..")
  ) {
    throw new McpAuthConfigError(
      `paths.${name} must be one absolute path without //, \\, ?, #, dot segments or whitespace`,
    )
  }

  return path
}

/**
 * Work out every endpoint path, defaulting to paths under the issuer's path.
 *
 * @param issuerPath - The issuer's path without a trailing slash.
 * @param paths - Configured paths.
 * @returns Every path.
 * @throws {McpAuthConfigError} When a path is invalid or two paths are equal.
 * @internal
 */
export function resolvePaths(
  issuerPath: string,
  paths: RoutePaths = {},
): Required<RoutePaths> {
  const pick = (key: keyof RoutePaths): string =>
    checkPath(key, paths[key] ?? `${issuerPath}/${key}`)
  const resolved: Required<RoutePaths> = {
    authorize: pick("authorize"),
    callback: pick("callback"),
    consent: pick("consent"),
    token: pick("token"),
    register: pick("register"),
    revoke: pick("revoke"),
  }
  const all = Object.values(resolved)

  if (new Set(all).size !== all.length) {
    throw new McpAuthConfigError("paths must be distinct")
  }

  return resolved
}
