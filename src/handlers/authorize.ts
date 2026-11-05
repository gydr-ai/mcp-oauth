import type { ErrorPageReason } from "../constants/error-pages.js"
import { resolveClient } from "../core/clients.js"
import { decide } from "../core/policy.js"
import { bindingCookieName, hostCookie } from "../helpers/cookies.js"
import { frozenCopy } from "../helpers/freeze.js"
import { groupParams, repeatedDefined, single } from "../helpers/params.js"
import { matchesAnyRedirectUri } from "../helpers/redirect-uris.js"
import { sameResource } from "../helpers/resource.js"
import { redirect } from "../helpers/responses.js"
import { resolveScopes } from "../helpers/scopes.js"
import {
  isWellFormedChallenge,
  pkceChallenge,
  randomToken,
  sha256Hex,
} from "../helpers/tokens.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { PendingAuthorization } from "../interfaces/records.js"

/** Parameters this endpoint defines; only these may not be repeated. */
const AUTHORIZE_PARAMETERS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "resource",
  "scope",
  "state",
  "prompt",
] as const

/**
 * `GET /authorize`: validate the request and send the browser to the
 * identity provider.
 *
 * Every problem found here is shown as a page in the browser, never sent to
 * the client's redirect URI: the person has not signed in yet, and
 * redirecting an unauthenticated request with an error would make this
 * endpoint an open redirector for any registered (or self-registered) client
 * (RFC 9700 § 4.11.2, OAuth 2.1 § 7.13.2). Errors are returned to the client
 * only after sign-in, from the callback and consent steps.
 *
 * On success the request is saved under a fresh flow id, a cookie ties the
 * flow to this browser, and the identity provider receives the flow id as
 * `state` together with this server's own PKCE challenge and nonce.
 *
 * @param context - Context supplying clients, policy hooks, the identity provider, store and cookie prefix.
 * @param request - The `GET /authorize` request opened in the person's browser; its query is unvalidated.
 * @returns A redirect to the identity provider, or an error page.
 * @internal
 */
export async function handleAuthorize(
  context: HandlerContext,
  request: Request,
): Promise<Response> {
  const { options } = context
  const { limits } = options

  if (!(await context.allowed(request, "authorize"))) {
    return context.errorPage(request, "rate_limited")
  }

  const params = groupParams(new URL(request.url).searchParams)
  const refuse = async (
    reason: ErrorPageReason,
    clientId?: string,
    extra: { detail?: string; policyReason?: string } = {},
  ) => {
    await context.emit({
      type: "authorization_refused",
      reason,
      ...(clientId !== undefined ? { clientId } : {}),
    })

    return context.errorPage(request, reason, extra)
  }

  // A defined parameter may appear once (OAuth 2.1 § 3.1). Two different
  // `redirect_uri` or `client_id` values could be read differently by
  // different parsers. Unknown parameters are ignored, even when repeated.
  if (repeatedDefined(params, AUTHORIZE_PARAMETERS).length > 0) {
    return refuse("repeated_parameter")
  }

  const clientId = single(params, "client_id")
  const client =
    clientId === undefined ? undefined : await resolveClient(context, clientId)

  if (clientId === undefined || client === undefined) {
    return refuse("client_unknown")
  }

  // OAuth 2.1 § 4.1.1: `redirect_uri` may be left out when the client has
  // exactly one registered; that one is then used.
  const sent = single(params, "redirect_uri")
  const [onlyRegistered] =
    client.redirectUris.length === 1 ? client.redirectUris : []
  const redirectUri = sent ?? onlyRegistered

  if (
    redirectUri === undefined ||
    !matchesAnyRedirectUri(client.redirectUris, redirectUri, limits)
  ) {
    return refuse("redirect_uri_not_registered", clientId)
  }

  const state = single(params, "state")

  if (state !== undefined && state.length > limits.stateLength) {
    return refuse("invalid_request", clientId, {
      detail: `The state value exceeds ${limits.stateLength} characters`,
    })
  }

  if (single(params, "response_type") !== "code") {
    return refuse("unsupported_response_type", clientId, {
      detail: "Only the authorization code flow is offered",
    })
  }

  const codeChallenge = single(params, "code_challenge")

  if (codeChallenge === undefined || !isWellFormedChallenge(codeChallenge)) {
    return refuse("invalid_request", clientId, {
      detail: "A 43-character S256 code_challenge must accompany the request",
    })
  }

  if (single(params, "code_challenge_method") !== "S256") {
    return refuse("invalid_request", clientId, {
      detail: "The only accepted code_challenge_method is S256",
    })
  }

  const resource = single(params, "resource")

  if (resource === undefined || !sameResource(options.resource, resource)) {
    return refuse("invalid_target", clientId, {
      detail: `Tokens from this server are only for ${options.resource}`,
    })
  }

  // Clients that declared a scope at registration stay inside it.
  const permitted = client.scopes ?? options.scopes
  const fallback = options.defaultScopes.filter((s) => permitted.includes(s))
  const scopes = resolveScopes(
    params.get("scope")?.[0],
    permitted,
    fallback.length > 0 ? fallback : permitted,
    limits.scopeLength,
  )

  if (scopes === undefined) {
    return refuse("invalid_scope", clientId)
  }

  // The person is always asked, so a request that forbids any interaction
  // (`prompt=none`) can never succeed.
  if (single(params, "prompt")?.split(" ").includes("none")) {
    return refuse("consent_required", clientId)
  }

  // The operator's own policy runs last and can only refuse.
  const policy = options.authorizeClient

  if (policy !== undefined) {
    const outcome = await decide(() =>
      policy({
        client: frozenCopy(client),
        redirectUri,
        scopes: frozenCopy(scopes),
        request,
      }),
    )

    if (!outcome.allowed) {
      return refuse(
        "access_denied",
        clientId,
        outcome.reason === undefined ? {} : { policyReason: outcome.reason },
      )
    }
  }

  const flowId = randomToken()
  const binding = randomToken()
  const upstreamVerifier = randomToken()
  const nonce = randomToken()
  const pending: PendingAuthorization = {
    id: flowId,
    clientId: client.clientId,
    clientKind: client.kind,
    redirectUri,
    codeChallenge,
    // Always the configured spelling, whatever case the client used.
    resource: options.resource,
    scopes,
    upstreamCodeVerifier: upstreamVerifier,
    upstreamNonce: nonce,
    bindingHash: sha256Hex(binding),
    allowRefresh: client.grantTypes?.includes("refresh_token") ?? true,
    expiresAt: options.now() + options.pendingTtlMs,
    ...(client.clientName !== undefined
      ? { clientName: client.clientName }
      : {}),
    ...(state !== undefined ? { state } : {}),
  }

  await options.store.putPendingAuthorization(pending)

  const location = await options.identityProvider.authorizationUrl({
    state: flowId,
    codeChallenge: pkceChallenge(upstreamVerifier),
    redirectUri: options.callbackUrl,
    nonce,
  })

  await context.emit({
    type: "authorization_started",
    clientId: client.clientId,
    scopes,
  })

  return redirect(location, [
    hostCookie(
      bindingCookieName(options.cookiePrefix, flowId),
      binding,
      Math.ceil(options.pendingTtlMs / 1000),
    ),
  ])
}
