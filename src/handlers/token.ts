import { readPublicClientForm } from "../core/client-form.js"
import { resolveClient } from "../core/clients.js"
import { exchangeCode } from "../core/code-exchange.js"
import { exchangeRefreshToken } from "../core/refresh-exchange.js"
import { EndpointRefusal } from "../errors/endpoint-refusal.js"
import { isMetadataDocumentClientId } from "../helpers/client-fields.js"
import { single } from "../helpers/params.js"
import { json, oauthError } from "../helpers/responses.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { RevokeGrant } from "../interfaces/routes.js"
import type { TokenResponse } from "../interfaces/token-response.js"

/** Parameters the token endpoint defines (besides client authentication). */
const TOKEN_PARAMETERS: readonly string[] = [
  "grant_type",
  "code",
  "redirect_uri",
  "code_verifier",
  "refresh_token",
  "scope",
  "resource",
]

/**
 * `POST /token`. Callers identify themselves by `client_id` alone and prove
 * possession with PKCE; codes and refresh tokens are exchanged here. Errors use
 * the RFC 6749 § 5.2 format. `invalid_client` is a 400, except a 401 with a
 * `WWW-Authenticate` challenge in the scheme the client used when it sent an
 * `Authorization` header (RFC 6749 § 5.2).
 *
 * @param context - Context supplying the store, clients, clock and token settings.
 * @param request - The `POST` to the token endpoint, with a form body.
 * @param revoke - Ends a grant; used for code and refresh-token replay and mismatches.
 * @returns The token response or an OAuth error.
 * @internal
 */
export async function handleToken(
  context: HandlerContext,
  request: Request,
  revoke: RevokeGrant,
): Promise<Response> {
  let clientId: string | undefined

  try {
    if (!(await context.allowed(request, "token"))) {
      return oauthError(
        429,
        "temporarily_unavailable",
        "Request rate exceeded; retry later",
      )
    }

    const parsed = await readPublicClientForm(
      request,
      context.options.limits.formBytes,
      TOKEN_PARAMETERS,
    )

    clientId = parsed.clientId

    if (clientId === undefined) {
      throw new EndpointRefusal(
        "invalid_client",
        "Missing parameter: client_id",
      )
    }

    // Registered clients must still exist. A metadata-document client was
    // checked at /authorize, and its code and tokens are tied to it.
    const byUrl = isMetadataDocumentClientId(clientId)
    const client = byUrl ? undefined : await resolveClient(context, clientId)

    if (!byUrl && client === undefined) {
      throw new EndpointRefusal(
        "invalid_client",
        "No client is registered under this client_id",
      )
    }

    const grantType = single(parsed.form, "grant_type")

    if (
      grantType === "refresh_token" &&
      client?.grantTypes !== undefined &&
      !client.grantTypes.includes("refresh_token")
    ) {
      throw new EndpointRefusal(
        "unauthorized_client",
        "refresh_token is not among this client's registered grant_types",
      )
    }

    let tokens: TokenResponse

    switch (grantType) {
      case "authorization_code":
        tokens = await exchangeCode(context, parsed.form, clientId, revoke)
        break
      case "refresh_token":
        tokens = await exchangeRefreshToken(
          context,
          parsed.form,
          clientId,
          revoke,
        )
        break
      case undefined:
        throw new EndpointRefusal(
          "invalid_request",
          "Missing parameter: grant_type",
        )
      default:
        throw new EndpointRefusal(
          "unsupported_grant_type",
          "This server only exchanges authorization codes and refresh tokens",
        )
    }

    return json(200, tokens, { cors: true })
  } catch (error) {
    if (!(error instanceof EndpointRefusal)) throw error

    await context.emit({
      type: "token_request_refused",
      error: error.error,
      reason: error.detail ?? error.description,
      ...(clientId !== undefined ? { clientId } : {}),
    })

    return oauthError(
      error.status,
      error.error,
      error.description,
      error.challenge,
    )
  }
}
