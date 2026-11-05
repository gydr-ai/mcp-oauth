import { EndpointRefusal } from "../errors/endpoint-refusal.js"
import { single, type Params } from "../helpers/params.js"
import { isOpaqueToken, sha256Hex } from "../helpers/tokens.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { RevokeGrant } from "../interfaces/routes.js"
import type { TokenResponse } from "../interfaces/token-response.js"
import { requireOwnResource } from "./client-form.js"
import { issueTokenPair, liveGrant } from "./grants.js"
import { requireTokenIssue } from "./token-policy.js"
import { hasExpired } from "../helpers/time.js"

/**
 * Exchange a refresh token for a new access token and a rotated refresh
 * token (OAuth 2.1 § 4.3).
 *
 * @param context - Context supplying the store, clock, retry window, hooks and token lifetimes.
 * @param form - Parsed token-endpoint form, already checked for repeated parameters and client credentials.
 * @param clientId - The `client_id` sent with the request; the refresh token must have been issued to it.
 * @param revoke - Ends a grant; used when a spent refresh token is presented again outside the retry window.
 * @returns The RFC 6749 § 5.1 token response with a rotated refresh token.
 * @throws {EndpointRefusal} When the token is missing, unknown, expired, another client's, replayed, asks for wider scopes, or its grant is gone.
 * @internal
 */
export async function exchangeRefreshToken(
  context: HandlerContext,
  form: Params,
  clientId: string,
  revoke: RevokeGrant,
): Promise<TokenResponse> {
  const { options } = context
  const presented = single(form, "refresh_token")

  if (presented === undefined) {
    throw new EndpointRefusal(
      "invalid_request",
      "Missing parameter: refresh_token",
    )
  }

  requireOwnResource(context, form)

  const unusable = () =>
    new EndpointRefusal("invalid_grant", "This refresh token cannot be used")

  if (!isOpaqueToken(presented)) throw unusable()

  const hash = sha256Hex(presented)
  const now = options.now()
  // Look before marking: a different client presenting the token must not
  // be able to use it up.
  const known = await options.store.getRefreshToken(hash)

  if (
    known === undefined ||
    known.clientId !== clientId ||
    hasExpired(known.expiresAt, now)
  ) {
    throw unusable()
  }

  let scopes = known.scopes
  const narrowed = single(form, "scope")

  if (narrowed !== undefined) {
    const asked = [...new Set(narrowed.split(" ").filter((s) => s.length > 0))]

    if (asked.length === 0 || asked.some((s) => !known.scopes.includes(s))) {
      throw new EndpointRefusal(
        "invalid_scope",
        "A refreshed token can only carry scopes already granted",
      )
    }

    scopes = asked
  }

  // Checked before the token is marked used, so a refusal or a failing
  // check leaves it usable.
  const current = await liveGrant(context, known.grantId, clientId)

  if (current === undefined || current.allowRefresh === false) {
    throw new EndpointRefusal("invalid_grant", "Access has been withdrawn")
  }

  await requireTokenIssue(context, current, "refresh_token")

  const marked = await options.store.useRefreshToken(hash, now)

  if (marked === undefined) throw unusable()

  const earlier = marked.previousUsedAt
  const withinRetryWindow =
    earlier !== undefined &&
    options.refreshReuseGraceMs > 0 &&
    now - earlier <= options.refreshReuseGraceMs

  if (earlier !== undefined && !withinRetryWindow) {
    // Presented again after it was spent, outside the retry window: assume
    // it was copied and withdraw everything issued under it (OAuth 2.1 § 4.3.1,
    // RFC 9700 § 4.14).
    await context.emit({
      type: "refresh_token_replayed",
      grantId: marked.record.grantId,
      clientId,
    })
    await revoke(marked.record.grantId, "refresh_token_replay")

    throw unusable()
  }

  const grant = await liveGrant(context, marked.record.grantId, clientId)

  if (grant === undefined || grant.allowRefresh === false) {
    throw new EndpointRefusal("invalid_grant", "Access has been withdrawn")
  }

  // A narrowed request narrows only this access token; the new refresh
  // token keeps the scopes it replaces (OAuth 2.1 § 4.3.1, RFC 6749 § 6).
  const tokens = await issueTokenPair(context, grant, scopes, known.scopes)

  await context.emit({
    type: "token_issued",
    grantId: grant.grantId,
    clientId,
    subject: grant.subject,
    grantType: "refresh_token",
  })

  return tokens
}
