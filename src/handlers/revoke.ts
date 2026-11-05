import { readPublicClientForm } from "../core/client-form.js"
import { EndpointRefusal } from "../errors/endpoint-refusal.js"
import { single } from "../helpers/params.js"
import { oauthError } from "../helpers/responses.js"
import { isOpaqueToken, sha256Hex } from "../helpers/tokens.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { RevokeGrant } from "../interfaces/routes.js"

const DONE_HEADERS: Readonly<Record<string, string>> = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
  "Access-Control-Allow-Origin": "*",
}

/** Parameters the revocation endpoint defines (RFC 7009 § 2.1). */
const REVOKE_PARAMETERS: readonly string[] = ["token", "token_type_hint"]

/**
 * `POST /revoke` (RFC 7009). The answer is `200` whether or not the token was
 * known, so the endpoint cannot be used to probe for tokens (§ 2.2).
 *
 * A refresh token ends its whole grant. An access token is deleted on its
 * own. If the caller names a `client_id`, only that client's tokens are
 * affected.
 *
 * @param context - Context supplying the store and size limits.
 * @param request - The `POST` to the revocation endpoint, with a form body.
 * @param revoke - Ends a grant; called when a refresh token is revoked.
 * @returns A 200 response or an OAuth error.
 * @internal
 */
export async function handleRevoke(
  context: HandlerContext,
  request: Request,
  revoke: RevokeGrant,
): Promise<Response> {
  const { store, limits } = context.options
  const done = () => new Response(null, { status: 200, headers: DONE_HEADERS })

  try {
    if (!(await context.allowed(request, "revoke"))) {
      return oauthError(
        429,
        "temporarily_unavailable",
        "Request rate exceeded; retry later",
      )
    }

    const { form, clientId } = await readPublicClientForm(
      request,
      limits.formBytes,
      REVOKE_PARAMETERS,
    )
    const token = single(form, "token")

    if (token === undefined) {
      throw new EndpointRefusal("invalid_request", "Missing parameter: token")
    }

    if (!isOpaqueToken(token)) return done()

    const hash = sha256Hex(token)
    const callerMayAct = (owner: string) =>
      clientId === undefined || clientId === owner
    const asRefreshToken = async () => {
      const found = await store.getRefreshToken(hash)

      if (found === undefined || !callerMayAct(found.clientId)) return false

      await revoke(found.grantId, "revocation_request")

      return true
    }
    const asAccessToken = async () => {
      const found = await store.getAccessToken(hash)

      if (found === undefined || !callerMayAct(found.clientId)) return false

      await store.deleteAccessToken(hash)

      return true
    }
    const order =
      single(form, "token_type_hint") === "access_token"
        ? [asAccessToken, asRefreshToken]
        : [asRefreshToken, asAccessToken]

    for (const attempt of order) {
      if (await attempt()) break
    }

    return done()
  } catch (error) {
    if (!(error instanceof EndpointRefusal)) throw error

    return oauthError(
      error.status,
      error.error,
      error.description,
      error.challenge,
    )
  }
}
