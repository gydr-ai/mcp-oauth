import { isOpaqueToken, sha256Hex } from "../helpers/tokens.js"
import type { AuthResult, BearerError } from "../interfaces/auth.js"
import type { HandlerContext } from "../interfaces/context.js"
import { grantContextFor } from "./grant-context.js"
import { liveGrant } from "./grants.js"
import { hasExpired } from "../helpers/time.js"

/**
 * Quote a value for an `auth-param` (RFC 9110 § 11.4), escaping quotes and
 * backslashes and folding line breaks.
 *
 * @param value - The raw value.
 * @returns The quoted string.
 */
function quoted(value: string): string {
  return `"${value.replace(/[\\"]/g, "\\$&").replace(/[\r\n]/g, " ")}"`
}

/**
 * HTTP status for a bearer error (RFC 6750 § 3.1).
 *
 * @param error - The error code, if any.
 * @returns 400, 401 or 403.
 */
function challengeStatus(error: BearerError["error"]): number {
  switch (error) {
    case "insufficient_scope":
      return 403
    case "invalid_request":
      return 400
    case "invalid_token":
    case undefined:
      return 401
  }
}

/**
 * A 401 (or 403 for `insufficient_scope`) carrying
 * `WWW-Authenticate: Bearer resource_metadata="…"` (RFC 6750 and RFC 9728
 * § 5.1), so an MCP client can discover the authorization server.
 *
 * @param context - Context supplying the resource metadata URL and default scopes for the challenge.
 * @param error - What to report.
 * @returns A JSON response with status 400, 401 or 403 and the `WWW-Authenticate: Bearer` header.
 * @internal
 */
export function bearerChallenge(
  context: HandlerContext,
  error: BearerError = {},
): Response {
  const { options } = context
  const params = [`resource_metadata=${quoted(options.resourceMetadataUrl)}`]
  const scope = error.scope ?? options.defaultScopes

  if (error.error !== undefined) params.push(`error=${quoted(error.error)}`)

  if (error.description !== undefined) {
    params.push(`error_description=${quoted(error.description)}`)
  }

  params.push(`scope=${quoted(scope.join(" "))}`)

  const status = challengeStatus(error.error)

  return new Response(
    JSON.stringify({
      error: error.error ?? "unauthorized",
      ...(error.description !== undefined
        ? { error_description: error.description }
        : {}),
    }),
    {
      status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "WWW-Authenticate": `Bearer ${params.join(", ")}`,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "WWW-Authenticate",
      },
    },
  )
}

/**
 * A generic 500 for a request the server could not finish, with no detail.
 *
 * @returns A JSON `server_error` response that is never cached.
 */
function serverFailure(): Response {
  return new Response(JSON.stringify({ error: "server_error" }), {
    status: 500,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  })
}

/**
 * The bearer token of a request.
 *
 * @param request - The request.
 * @returns The token; `null` when no Bearer credentials were sent (no
 *   `Authorization` header, or one with another scheme); `undefined` when a
 *   Bearer credential is empty.
 */
function bearerToken(request: Request): string | null | undefined {
  const header = request.headers.get("authorization")

  if (header === null) return null

  const trimmed = header.trim()
  const space = trimmed.indexOf(" ")
  const scheme = space === -1 ? trimmed : trimmed.slice(0, space)

  // RFC 6750 § 3.1: a request without Bearer credentials gets the bare
  // challenge, with no error code.
  if (scheme.toLowerCase() !== "bearer") return null

  const token = space === -1 ? "" : trimmed.slice(space + 1).trim()

  return token === "" ? undefined : token
}

/**
 * Check the bearer token on a request to the protected resource. It must be
 * a token this server issued, not expired, addressed to this resource
 * (RFC 8707 audience), and its grant must still exist for the same client.
 *
 * @param context - Context supplying the store, clock, configured resource and `getGrantContext` hook.
 * @param request - The request.
 * @param upstream - Produces an upstream access token for a grant id.
 * @returns The outcome. When `getGrantContext` throws, returns data that is
 *   not JSON-serializable, or exceeds `limits.grantContextBytes`, the result
 *   is a failure with a generic 500 response and a `grant_context_failed`
 *   event; the hook's error never leaves this function.
 * @internal
 */
export async function authenticateRequest(
  context: HandlerContext,
  request: Request,
  upstream: (grantId: string, forceRefresh: boolean) => Promise<string>,
): Promise<AuthResult> {
  const { options } = context
  const token = bearerToken(request)

  if (token === null) {
    return { ok: false, response: bearerChallenge(context) }
  }

  const invalid = (description: string): AuthResult => ({
    ok: false,
    response: bearerChallenge(context, { error: "invalid_token", description }),
  })

  if (token === undefined || !isOpaqueToken(token)) {
    return invalid("The bearer value is not in this server's token format")
  }

  const row = await options.store.getAccessToken(sha256Hex(token))

  if (row === undefined || hasExpired(row.expiresAt, options.now())) {
    return invalid("The token is unknown here or past its expiry")
  }

  if (row.resource !== options.resource) {
    return invalid("The token's audience is a different resource")
  }

  const grant = await liveGrant(context, row.grantId, row.clientId)

  if (grant === undefined) {
    return invalid("Access behind this token has been withdrawn")
  }

  let grantContext: unknown

  try {
    grantContext = await grantContextFor(context, grant)
  } catch {
    // The hook's message may contain anything; it is neither logged nor
    // returned, so a host error handler cannot leak it.
    await context.emit({ type: "grant_context_failed", grantId: grant.grantId })

    return { ok: false, response: serverFailure() }
  }

  return {
    ok: true,
    subject: grant.subject,
    grantId: grant.grantId,
    clientId: grant.clientId,
    scopes: row.scopes,
    context: grantContext,
    getUpstreamAccessToken: (options) =>
      upstream(grant.grantId, options?.forceRefresh === true),
  }
}
