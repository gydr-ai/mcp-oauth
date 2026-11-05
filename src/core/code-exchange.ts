import { EndpointRefusal } from "../errors/endpoint-refusal.js"
import { single, type Params } from "../helpers/params.js"
import { sameResource } from "../helpers/resource.js"
import { hasExpired } from "../helpers/time.js"
import { isOpaqueToken, pkceMatches, sha256Hex } from "../helpers/tokens.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { RevokeGrant } from "../interfaces/routes.js"
import type { TokenResponse } from "../interfaces/token-response.js"
import { requireOwnResource } from "./client-form.js"
import { issueTokenPair, liveGrant } from "./grants.js"
import { requireTokenIssue } from "./token-policy.js"

/**
 * Exchange an authorization code (OAuth 2.1 § 4.1.3).
 *
 * The code is first READ, and the client, `redirect_uri` (when sent),
 * `resource` (when sent) and PKCE verifier are compared with it. A mismatch
 * is refused without using the code up or touching the grant: whoever holds
 * a stolen code can neither spend it nor end the person's session by
 * guessing verifiers, and guessing one (256 bits for a 43-character
 * verifier, under the token endpoint's rate limit) is hopeless. Only a
 * fully matching request consumes the code, atomically: the first gets
 * tokens; a later, fully valid one is a replay and ends the grant
 * (OAuth 2.1 § 4.1.3, RFC 9700 § 4.5.3.1).
 *
 * @param context - Context supplying the store, clock, hooks and token lifetimes.
 * @param form - Parsed token-endpoint form, already checked for repeated parameters and client credentials.
 * @param clientId - The `client_id` sent with the request; for stored clients it was confirmed to exist.
 * @param revoke - Ends a grant; used when a code is replayed or presented after it expired.
 * @returns The RFC 6749 § 5.1 token response for the code's grant.
 * @throws {EndpointRefusal} When a parameter is missing, the code is unknown, replayed or expired, a value differs from the authorization, `beforeTokenIssue` refuses, or the grant is gone.
 * @internal
 */
export async function exchangeCode(
  context: HandlerContext,
  form: Params,
  clientId: string,
  revoke: RevokeGrant,
): Promise<TokenResponse> {
  const { options } = context
  const code = single(form, "code")
  const verifier = single(form, "code_verifier")
  // Optional: OAuth 2.1 binds the code to the client and PKCE instead.
  const redirectUri = single(form, "redirect_uri")
  const missing = [
    code === undefined ? "code" : undefined,
    verifier === undefined ? "code_verifier" : undefined,
  ].filter((name) => name !== undefined)

  if (code === undefined || verifier === undefined) {
    throw new EndpointRefusal(
      "invalid_request",
      `Missing parameter: ${missing.join(", ")}`,
    )
  }

  requireOwnResource(context, form)

  // One answer for an unknown, expired, replayed or mismatched code, so
  // the response says nothing about which check failed; the event does.
  const unusable = (detail: string) =>
    new EndpointRefusal(
      "invalid_grant",
      "This authorization code cannot be exchanged",
      400,
      undefined,
      detail,
    )

  if (!isOpaqueToken(code)) throw unusable("code_malformed")

  const codeHash = sha256Hex(code)
  const stored = await options.store.getAuthorizationCode(codeHash)

  if (stored === undefined) throw unusable("code_unknown")

  const issued = stored.record
  const resource = single(form, "resource")
  // Checked in this order; the first that differs is reported.
  const comparisons: readonly (readonly [string, boolean])[] = [
    ["client_id", issued.clientId !== clientId],
    [
      "redirect_uri",
      redirectUri !== undefined && issued.redirectUri !== redirectUri,
    ],
    [
      "resource",
      resource !== undefined && !sameResource(issued.resource, resource),
    ],
    ["code_verifier", !pkceMatches(verifier, issued.codeChallenge)],
  ]
  const differs = comparisons.find(([, mismatch]) => mismatch)?.[0]

  if (differs !== undefined) {
    throw unusable(`${differs}_mismatch`)
  }

  const replayed = async () => {
    // A second fully valid redemption means someone else holds the code
    // and its verifier too: undo everything it led to.
    await context.emit({
      type: "authorization_code_replayed",
      grantId: issued.grantId,
      clientId: issued.clientId,
    })
    await revoke(issued.grantId, "authorization_code_replay")

    return unusable("code_replayed")
  }

  if (stored.consumed) throw await replayed()

  if (hasExpired(issued.expiresAt, options.now())) {
    await revoke(issued.grantId, "authorization_code_expired")

    throw unusable("code_expired")
  }

  const grant = await liveGrant(context, issued.grantId, clientId)

  if (grant === undefined) {
    throw new EndpointRefusal("invalid_grant", "Access has been withdrawn")
  }

  await requireTokenIssue(context, grant, "authorization_code")

  const redeemed = await options.store.consumeAuthorizationCode(codeHash)

  if (redeemed === undefined) throw unusable("code_unknown")

  if (!redeemed.firstUse) throw await replayed()

  const tokens = await issueTokenPair(context, grant, issued.scopes)

  await context.emit({
    type: "token_issued",
    grantId: grant.grantId,
    clientId,
    subject: grant.subject,
    grantType: "authorization_code",
  })

  return tokens
}
