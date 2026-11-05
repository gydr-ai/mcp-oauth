import { LOOPBACK_HOSTS } from "../constants/protocol.js"
import { IdentityProviderError } from "../errors/identity-provider-error.js"
import { isRecord, isStringArray } from "../helpers/guards.js"
import type { Discovery, TokenEndpointResponse } from "../interfaces/oidc.js"

function optionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === "string"
}

/**
 *
 * @param value - Parsed JSON from the provider's `/.well-known/openid-configuration`.
 * @returns `true` for a usable discovery document.
 * @internal
 */
export function isDiscovery(value: unknown): value is Discovery {
  return (
    isRecord(value) &&
    typeof value.issuer === "string" &&
    typeof value.authorization_endpoint === "string" &&
    typeof value.token_endpoint === "string" &&
    typeof value.jwks_uri === "string" &&
    optionalString(value.revocation_endpoint) &&
    (value.token_endpoint_auth_methods_supported === undefined ||
      isStringArray(value.token_endpoint_auth_methods_supported)) &&
    (value.authorization_response_iss_parameter_supported === undefined ||
      typeof value.authorization_response_iss_parameter_supported ===
        "boolean") &&
    (value.code_challenge_methods_supported === undefined ||
      isStringArray(value.code_challenge_methods_supported))
  )
}

/**
 *
 * @param value - Parsed JSON from the provider's token endpoint.
 * @returns `true` for a usable token response.
 * @internal
 */
export function isTokenResponse(
  value: unknown,
): value is TokenEndpointResponse {
  return (
    isRecord(value) &&
    typeof value.access_token === "string" &&
    value.access_token !== "" &&
    optionalString(value.id_token) &&
    optionalString(value.refresh_token) &&
    (value.expires_in === undefined ||
      (typeof value.expires_in === "number" &&
        Number.isFinite(value.expires_in)))
  )
}

/**
 *
 * @param name - Discovery field name, used in the error message (for example `token_endpoint`).
 * @param value - The endpoint URL as published by the provider.
 * @param insecure - Whether `http` is allowed for loopback hosts (`allowInsecureLocalhost`).
 * @returns The parsed URL, known to be `https` (or loopback `http` when allowed).
 * @throws {IdentityProviderError} When the value is not a URL or is not `https` (loopback `http` only when allowed).
 * @internal
 */
export function checkEndpoint(
  name: string,
  value: string,
  insecure: boolean,
): URL {
  let url: URL

  try {
    url = new URL(value)
  } catch {
    throw new IdentityProviderError(
      `Identity provider ${name} cannot be parsed as a URL`,
    )
  }

  const local = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)

  if (url.protocol !== "https:" && !(local && insecure)) {
    throw new IdentityProviderError(
      `Identity provider ${name} is not an https URL`,
    )
  }

  return url
}
