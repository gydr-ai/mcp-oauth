/**
 * ID token signature algorithms accepted by default: asymmetric only.
 *
 * @internal
 */
export const DEFAULT_ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
]

/**
 * Authorization parameters this library sets itself and never lets callers override.
 *
 * @internal
 */
export const RESERVED_PARAMS: ReadonlySet<string> = new Set([
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "client_id",
  "redirect_uri",
  "response_type",
  "scope",
])
