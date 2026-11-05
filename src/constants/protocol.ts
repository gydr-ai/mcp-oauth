/**
 * Well-known path of RFC 9728 protected resource metadata.
 *
 * @internal
 */
export const PROTECTED_RESOURCE_METADATA_PATH =
  "/.well-known/oauth-protected-resource"

/**
 * Well-known path of RFC 8414 authorization server metadata.
 *
 * @internal
 */
export const AUTHORIZATION_SERVER_METADATA_PATH =
  "/.well-known/oauth-authorization-server"

/**
 * Hostnames treated as the local machine (RFC 8252 § 7.3).
 *
 * @internal
 */
export const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
  "127.0.0.1",
  "[::1]",
  "localhost",
])

/**
 * Names of the fields the consent form posts back.
 *
 * @internal
 */
export const CONSENT_FIELDS = {
  id: "interaction",
  csrf: "form_token",
  decision: "choice",
} as const

/**
 * The value of the decision field that grants access.
 *
 * @internal
 */
export const CONSENT_APPROVE = "approve"

/**
 * Media type of form bodies.
 *
 * @internal
 */
export const FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"

/**
 * Media type of JSON bodies.
 *
 * @internal
 */
export const JSON_MEDIA_TYPE = "application/json"
