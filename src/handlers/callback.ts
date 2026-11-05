import { randomUUID } from "node:crypto"

import { UPSTREAM_LIFETIME_CEILING_SECONDS } from "../constants/defaults.js"
import { consentPageResponse } from "../core/consent-page.js"
import { revokeUpstreamToken } from "../core/grants.js"
import { resolvePerson } from "../core/subject.js"
import {
  bindingCookieName,
  clearHostCookie,
  readCookie,
} from "../helpers/cookies.js"
import { frozenCopy } from "../helpers/freeze.js"
import { jsonCopy } from "../helpers/json.js"
import { groupParams, repeatedDefined, single } from "../helpers/params.js"
import { buildRedirect } from "../helpers/redirect-uris.js"
import { redirect } from "../helpers/responses.js"
import { hasExpired } from "../helpers/time.js"
import { constantTimeEqual, randomToken, sha256Hex } from "../helpers/tokens.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { UpstreamLogin } from "../interfaces/identity-provider.js"
import type { ConsentRequest } from "../interfaces/records.js"

/** Parameters an authorization response defines (RFC 6749 § 4.1.2, RFC 9207). */
const CALLBACK_PARAMETERS = [
  "state",
  "code",
  "error",
  "error_description",
  "error_uri",
  "iss",
] as const

/**
 * `GET /callback`: the identity provider returns the browser here.
 *
 * 1. The browser must carry the cookie set when the flow began; without it
 *    the request is refused and the flow is left untouched, so a person who
 *    only saw the `state` value cannot cancel someone else's sign-in.
 * 2. The flow is then taken from the store, once; a second callback finds
 *    nothing.
 * 3. The provider's code is exchanged, the upstream tokens are sealed for
 *    the grant id the person may approve, and the consent page is shown with
 *    a one-time form token.
 *
 * @param context - Context supplying the store, identity provider, sealer, hooks and pages.
 * @param request - The browser's return from the identity provider, with `state`, `code` or `error` in the query and the binding cookie.
 * @returns The consent page, a redirect to the client, or an error page.
 * @internal
 */
export async function handleCallback(
  context: HandlerContext,
  request: Request,
): Promise<Response> {
  const { options } = context

  if (!(await context.allowed(request, "callback"))) {
    return context.errorPage(request, "rate_limited")
  }

  const params = groupParams(new URL(request.url).searchParams)

  if (repeatedDefined(params, CALLBACK_PARAMETERS).length > 0) {
    return context.errorPage(request, "malformed_response")
  }

  const flowId = single(params, "state")

  if (flowId === undefined) return context.errorPage(request, "flow_ended")

  const cookieName = bindingCookieName(options.cookiePrefix, flowId)
  const dropCookie = clearHostCookie(cookieName)
  const observed = await options.store.getPendingAuthorization(flowId)

  if (observed === undefined || hasExpired(observed.expiresAt, options.now())) {
    return context.errorPage(request, "flow_ended")
  }

  const binding = readCookie(request, cookieName)

  if (
    binding === undefined ||
    !constantTimeEqual(sha256Hex(binding), observed.bindingHash)
  ) {
    await context.emit({ type: "flow_binding_mismatch", step: "callback" })

    return context.errorPage(request, "browser_mismatch", {
      setCookies: [dropCookie],
    })
  }

  const pending = await options.store.consumePendingAuthorization(flowId)

  if (
    pending === undefined ||
    hasExpired(pending.expiresAt, options.now()) ||
    pending.bindingHash !== observed.bindingHash
  ) {
    return context.errorPage(request, "flow_ended")
  }

  const providerError = single(params, "error")

  // The person went to the identity provider from this browser (the
  // binding cookie proves it) and came back; telling the client is not an
  // automatic redirect of an unauthenticated request.
  if (providerError !== undefined) {
    const cancelled = providerError === "access_denied"

    await context.emit({
      type: "identity_provider_error",
      clientId: pending.clientId,
      reason: cancelled ? "person_cancelled" : "provider_reported_error",
    })

    return redirect(
      buildRedirect(pending.redirectUri, {
        error: cancelled ? "access_denied" : "server_error",
        error_description: cancelled
          ? "The person stopped at the sign-in step"
          : "The identity provider could not complete the sign-in",
        state: pending.state,
        iss: options.issuer,
      }),
      [dropCookie],
    )
  }

  const code = single(params, "code")

  if (code === undefined) {
    return context.errorPage(request, "malformed_response", {
      setCookies: [dropCookie],
    })
  }

  const iss = single(params, "iss")
  let login: UpstreamLogin

  try {
    login = await options.identityProvider.exchangeCode({
      code,
      codeVerifier: pending.upstreamCodeVerifier,
      redirectUri: options.callbackUrl,
      nonce: pending.upstreamNonce,
      ...(iss !== undefined ? { issuer: iss } : {}),
    })
  } catch (error) {
    await context.emit({
      type: "identity_provider_error",
      clientId: pending.clientId,
      reason: error instanceof Error ? error.name : "exchange_failed",
    })

    return context.errorPage(request, "sign_in_not_confirmed", {
      setCookies: [dropCookie],
    })
  }

  const releaseUpstream = async () => {
    if (login.refreshToken !== undefined) {
      await revokeUpstreamToken(context, login.refreshToken)
    }
  }

  if (typeof login.subject !== "string" || login.subject.length === 0) {
    await releaseUpstream()
    await context.emit({
      type: "identity_provider_error",
      clientId: pending.clientId,
      reason: "subject_missing",
    })

    return context.errorPage(request, "sign_in_not_confirmed", {
      setCookies: [dropCookie],
    })
  }

  const client = {
    clientId: pending.clientId,
    kind: pending.clientKind,
    ...(pending.clientName !== undefined
      ? { clientName: pending.clientName }
      : {}),
  }
  const resolved = await resolvePerson(context, login, client)

  if (!resolved.ok) {
    await releaseUpstream()
    await context.emit({
      type: "identity_provider_error",
      clientId: pending.clientId,
      reason: "subject_not_permitted",
    })

    return context.errorPage(request, "subject_not_permitted", {
      setCookies: [dropCookie],
      ...(resolved.policyReason !== undefined
        ? { policyReason: resolved.policyReason }
        : {}),
    })
  }

  const { person } = resolved
  let details: unknown

  if (options.getConsentDetails !== undefined) {
    try {
      details = jsonCopy(
        await options.getConsentDetails(
          Object.freeze({
            ...frozenCopy({
              subject: person.subject,
              client,
              scopes: [...pending.scopes],
            }),
            request,
          }),
        ),
        options.limits.consentDetailsBytes,
        "getConsentDetails",
      )
    } catch {
      await releaseUpstream()

      return context.errorPage(request, "server_error", {
        setCookies: [dropCookie],
      })
    }
  }

  const now = options.now()
  const grantId = randomUUID()
  const formToken = randomToken()
  const { sealer } = options
  const lifetime =
    login.expiresIn !== undefined && Number.isFinite(login.expiresIn)
      ? Math.min(
          Math.max(login.expiresIn, 0),
          UPSTREAM_LIFETIME_CEILING_SECONDS,
        )
      : undefined
  const consent: ConsentRequest = {
    id: randomToken(),
    grantId,
    clientId: pending.clientId,
    clientKind: pending.clientKind,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    resource: pending.resource,
    scopes: pending.scopes,
    subject: person.subject,
    csrfHash: sha256Hex(formToken),
    bindingHash: pending.bindingHash,
    expiresAt: now + options.pendingTtlMs,
    ...(pending.allowRefresh !== undefined
      ? { allowRefresh: pending.allowRefresh }
      : {}),
    ...(pending.clientName !== undefined
      ? { clientName: pending.clientName }
      : {}),
    ...(pending.state !== undefined ? { state: pending.state } : {}),
    ...(person.displayName !== undefined
      ? { displayName: person.displayName }
      : {}),
    ...(details !== undefined ? { details } : {}),
    ...(login.refreshToken !== undefined
      ? {
          sealedUpstreamRefreshToken: await sealer.seal(
            login.refreshToken,
            grantId,
          ),
        }
      : {}),
    ...(login.accessToken !== undefined && lifetime !== undefined
      ? {
          sealedUpstreamAccessToken: await sealer.seal(
            login.accessToken,
            `${grantId}#access`,
          ),
          upstreamAccessTokenExpiresAt: now + lifetime * 1000,
        }
      : {}),
  }
  let response: Response

  // Render before storing: if a custom renderer throws, nothing holding the
  // sealed upstream token is left behind, and the token itself is revoked.
  try {
    response = consentPageResponse(context, request, consent, formToken, {
      binding,
      setCookies: [dropCookie],
    })
  } catch (error) {
    await releaseUpstream()
    throw error
  }

  await options.store.putConsentRequest(consent)

  return response
}
