import {
  CONSENT_APPROVE,
  CONSENT_FIELDS,
  FORM_MEDIA_TYPE,
} from "../constants/protocol.js"
import { consentPageResponse } from "../core/consent-page.js"
import { initialGrantExpiry } from "../core/grant-expiry.js"
import { grantSummary } from "../core/grant-summary.js"
import { revokeSealedUpstreamToken } from "../core/grants.js"
import { decide } from "../core/policy.js"
import { BodyTooLargeError } from "../errors/body-too-large-error.js"
import { hasContentType, readBody } from "../helpers/body.js"
import {
  bindingCookieName,
  clearHostCookie,
  readCookie,
} from "../helpers/cookies.js"
import { frozenCopy } from "../helpers/freeze.js"
import { isRecord } from "../helpers/guards.js"
import { jsonCopy } from "../helpers/json.js"
import {
  groupParams,
  repeatedDefined,
  single,
  type Params,
} from "../helpers/params.js"
import { buildRedirect } from "../helpers/redirect-uris.js"
import { redirect } from "../helpers/responses.js"
import { hasExpired } from "../helpers/time.js"
import { setTimeout as sleep } from "node:timers/promises"
import { constantTimeEqual, randomToken, sha256Hex } from "../helpers/tokens.js"
import type { HookClient } from "../interfaces/consent.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { ConsentRequest, GrantRecord } from "../interfaces/records.js"

/** How often a repeated submission looks for the first one's answer, in ms. */
const REPLAY_POLL_MS = 200

/** What a submission left for a repeat: its answer, or that it is still being decided. */
type RememberedAnswer =
  { readonly location: string } | { readonly pending: true }

/** The package's own consent form fields; never passed to `readConsentFields`. */
const RESERVED_FIELDS: readonly string[] = Object.values(CONSENT_FIELDS)

/** Most field errors `readConsentFields` may report. */
const FIELD_ERROR_LIMIT = 50

/** Longest field name or field error message accepted from `readConsentFields`. */
const FIELD_TEXT_LIMIT = 200

/**
 * The extra fields of a consent form: the first value of every field that is
 * not one of the package's own.
 *
 * @param form - The parsed consent form.
 * @returns Field name to value.
 */
function extraFields(form: Params): Record<string, string> {
  const fields: [string, string][] = []

  for (const [name, values] of form) {
    const [first] = values

    if (!RESERVED_FIELDS.includes(name) && first !== undefined) {
      fields.push([name, first])
    }
  }

  // Own data properties only: a field named `__proto__` stays a field.
  return Object.fromEntries(fields)
}

/**
 * Check what `readConsentFields` reported as field errors.
 *
 * @param value - The hook's `fieldErrors`, of unknown shape.
 * @returns 1–50 non-empty string messages by field name, or `undefined`
 *   when the value is not usable.
 */
function readFieldErrors(
  value: unknown,
): Readonly<Record<string, string>> | undefined {
  if (!isRecord(value)) return undefined

  const entries = Object.entries(value)

  if (entries.length === 0 || entries.length > FIELD_ERROR_LIMIT) {
    return undefined
  }

  const errors: [string, string][] = []

  for (const [name, message] of entries) {
    if (
      typeof message !== "string" ||
      message === "" ||
      message.length > FIELD_TEXT_LIMIT ||
      name.length > FIELD_TEXT_LIMIT
    ) {
      return undefined
    }

    errors.push([name, message])
  }

  return Object.fromEntries(errors)
}

/** What `readConsentFields` decided. */
type FieldsVerdict =
  | { readonly kind: "accepted"; readonly grantData: unknown }
  | {
      readonly kind: "correct"
      readonly fieldErrors: Readonly<Record<string, string>>
    }
  | { readonly kind: "failed" }

/**
 * The client of a consent request, as hooks see it.
 *
 * @param consent - The consent request.
 * @returns The client id, kind and name.
 */
function hookClient(consent: ConsentRequest): HookClient {
  return {
    clientId: consent.clientId,
    kind: consent.clientKind,
    ...(consent.clientName !== undefined
      ? { clientName: consent.clientName }
      : {}),
  }
}

/**
 * Run `readConsentFields`, if set, and validate its result.
 *
 * @param context - Context supplying the hook and `limits.grantDataBytes`.
 * @param consent - The verified consent request.
 * @param fields - The extra form fields.
 * @returns Accepted with grant data, a request to correct fields, or failed
 *   (the hook threw or returned something unusable).
 */
async function readFields(
  context: HandlerContext,
  consent: ConsentRequest,
  fields: Readonly<Record<string, string>>,
): Promise<FieldsVerdict> {
  const hook = context.options.readConsentFields

  if (hook === undefined) return { kind: "accepted", grantData: undefined }

  let result: unknown

  try {
    result = await hook(
      frozenCopy({
        form: { ...fields },
        details: consent.details,
        subject: consent.subject,
        client: hookClient(consent),
        scopes: [...consent.scopes],
      }),
    )
  } catch {
    return { kind: "failed" }
  }

  if (!isRecord(result)) return { kind: "failed" }

  switch (result.ok) {
    case true:
      try {
        return {
          kind: "accepted",
          grantData: jsonCopy(
            result.grantData,
            context.options.limits.grantDataBytes,
            "readConsentFields",
          ),
        }
      } catch {
        return { kind: "failed" }
      }
    case false: {
      const fieldErrors = readFieldErrors(result.fieldErrors)

      return fieldErrors === undefined
        ? { kind: "failed" }
        : { kind: "correct", fieldErrors }
    }
    default:
      return { kind: "failed" }
  }
}

/**
 * `POST /consent`: the person approves or declines.
 *
 * 1. The saved consent request is read, and the one-time form token and the
 *    browser cookie are compared in constant time before anything else runs.
 *    A mismatch, or an expired request, ends the flow and revokes the
 *    upstream token.
 * 2. On approval, `readConsentFields` may ask for corrections: the page is
 *    shown again and nothing is used up.
 * 3. The request is then taken from the store, once. A repeat of the same
 *    submission from the same browser within `consentReplaySeconds` gets the
 *    same redirect again, when the store supports it.
 * 4. `beforeGrant` may refuse; the grant and a one-time code are stored;
 *    `afterGrant` runs and, if it throws, the grant is removed again.
 *
 * Every answer to the client is a 303 redirect (OAuth 2.1 § 7.5.4: a
 * redirect after a form `POST` must not repeat the `POST`) carrying `iss`
 * (RFC 9207). Every outcome without a grant revokes the upstream refresh
 * token obtained at sign-in.
 *
 * @param context - Context supplying the store, sealer, clock, lifetimes, hooks, cookie prefix and pages.
 * @param request - The `POST` from the consent page, with a form body and the binding cookie.
 * @returns A 303 redirect to the client, the consent page again, or an error page.
 * @internal
 */
export async function handleConsent(
  context: HandlerContext,
  request: Request,
): Promise<Response> {
  const { options } = context

  if (!(await context.allowed(request, "consent"))) {
    return context.errorPage(request, "rate_limited")
  }

  // An extra check on top of the form token and the SameSite cookie. Pages
  // here use `Referrer-Policy: no-referrer`, under which browsers report
  // `Origin: null` for the form post; any concrete foreign origin means a
  // different site submitted the form.
  const origin = request.headers.get("origin")

  if (origin !== null && origin !== "null" && origin !== options.issuerOrigin) {
    return context.errorPage(request, "consent_unavailable")
  }

  if (!hasContentType(request, FORM_MEDIA_TYPE)) {
    return context.errorPage(request, "unsupported_submission")
  }

  let form: Params

  try {
    form = groupParams(
      new URLSearchParams(await readBody(request, options.limits.formBytes)),
    )
  } catch (error) {
    if (error instanceof BodyTooLargeError) {
      return context.errorPage(request, "consent_unavailable")
    }

    throw error
  }

  if (repeatedDefined(form, RESERVED_FIELDS).length > 0) {
    return context.errorPage(request, "consent_unavailable")
  }

  const interactionId = single(form, CONSENT_FIELDS.id)
  const formToken = single(form, CONSENT_FIELDS.csrf)

  if (interactionId === undefined || formToken === undefined) {
    return context.errorPage(request, "consent_unavailable")
  }

  const { store, sealer } = options
  const cookieName = bindingCookieName(options.cookiePrefix, interactionId)
  const dropCookie = clearHostCookie(cookieName)
  const binding = readCookie(request, cookieName)
  const ended = () =>
    context.errorPage(request, "consent_unavailable", {
      setCookies: [dropCookie],
    })
  // Names one submission from one browser: only the same form token sent
  // with the same cookie can see the answer it got.
  const replayKey =
    binding === undefined
      ? undefined
      : sha256Hex(`${sha256Hex(binding)}:${sha256Hex(formToken)}`)
  const remembers =
    replayKey !== undefined &&
    options.consentReplayMs > 0 &&
    store.putConsentOutcome !== undefined &&
    store.getConsentOutcome !== undefined
  // Remember this submission's answer, or that it is still being decided,
  // for a repeat from the same browser. Sealed: the location may carry an
  // authorization code. The expiry travels inside, so a store that keeps it
  // longer changes nothing.
  // Best effort: it only serves a repeat, so a failed write must never fail
  // the submission itself (a repeat then sees the error page).
  const remember = async (answer: RememberedAnswer): Promise<void> => {
    if (!remembers) return

    try {
      const expiresAt = options.now() + options.consentReplayMs

      await store.putConsentOutcome?.(
        replayKey,
        await sealer.seal(JSON.stringify({ ...answer, expiresAt }), replayKey),
        expiresAt,
      )
    } catch {
      // Nothing to undo; see above.
    }
  }
  // The last value read while polling: an unchanged "pending" mark is not
  // opened (decrypted) again.
  let lastSealed: string | undefined
  let lastAnswer: RememberedAnswer | undefined
  let lastExpiresAt = 0
  const recall = async (): Promise<RememberedAnswer | undefined> => {
    if (!remembers) return undefined

    const sealed = await store.getConsentOutcome?.(replayKey)

    if (sealed === undefined) return undefined

    if (sealed === lastSealed && lastAnswer !== undefined) {
      return "pending" in lastAnswer &&
        !hasExpired(lastExpiresAt, options.now())
        ? lastAnswer
        : undefined
    }

    let outcome: unknown

    try {
      outcome = JSON.parse(await sealer.open(sealed, replayKey))
    } catch {
      return undefined
    }

    // The window is enforced here, never left to the store's expiry.
    if (
      !isRecord(outcome) ||
      typeof outcome.expiresAt !== "number" ||
      hasExpired(outcome.expiresAt, options.now())
    ) {
      return undefined
    }

    lastSealed = sealed
    lastExpiresAt = outcome.expiresAt
    lastAnswer =
      outcome.pending === true
        ? { pending: true }
        : typeof outcome.location === "string"
          ? { location: outcome.location }
          : undefined

    return lastAnswer
  }
  // A repeat of a submission this browser already made. While the first is
  // still being decided, wait for its answer within the replay window. An
  // unverified repeat (`verified: false`) waits only once the first has left
  // its "pending" mark, so a forged one ends at once; a repeat whose form
  // token and browser cookie were just verified also waits for a mark the
  // first has not written yet (both took the same request a moment apart).
  const replay = async (verified: boolean): Promise<Response> => {
    if (!remembers) return ended()

    const attempts = Math.ceil(options.consentReplayMs / REPLAY_POLL_MS)

    for (let attempt = 0; ; attempt += 1) {
      const answer = await recall()

      if (answer !== undefined && "location" in answer) {
        return redirect(answer.location, [dropCookie], 303)
      }

      if (
        (answer === undefined && !verified) ||
        attempt >= attempts ||
        request.signal.aborted
      ) {
        return ended()
      }

      await sleep(REPLAY_POLL_MS)
    }
  }
  const consent = await store.getConsentRequest(interactionId)

  if (consent === undefined) return replay(false)

  const releaseUpstream = () =>
    revokeSealedUpstreamToken(
      context,
      consent.sealedUpstreamRefreshToken,
      consent.grantId,
    )
  const abandon = async (): Promise<void> => {
    await store.consumeConsentRequest(interactionId)
    await releaseUpstream()
  }

  if (hasExpired(consent.expiresAt, options.now())) {
    await abandon()

    return ended()
  }

  const tokenOk = constantTimeEqual(sha256Hex(formToken), consent.csrfHash)
  const browserOk =
    binding !== undefined &&
    constantTimeEqual(sha256Hex(binding), consent.bindingHash)

  if (!tokenOk || !browserOk) {
    await context.emit({ type: "flow_binding_mismatch", step: "consent" })
    await abandon()

    return ended()
  }

  const approve = single(form, CONSENT_FIELDS.decision) === CONSENT_APPROVE
  let grantData: unknown

  if (approve) {
    const fields = extraFields(form)
    const verdict = await readFields(context, consent, fields)

    switch (verdict.kind) {
      case "correct":
        // Shown again; the request stays usable for the corrected answer.
        return consentPageResponse(context, request, consent, formToken, {
          status: 400,
          fieldErrors: verdict.fieldErrors,
          submitted: { ...fields },
        })
      case "failed":
        await abandon()

        return context.errorPage(request, "server_error", {
          setCookies: [dropCookie],
        })
      case "accepted":
        grantData = verdict.grantData
        break
    }
  }

  // Taking the request is the one atomic step: of two concurrent
  // submissions only one gets it, and the other is answered like the first.
  const taken = await store.consumeConsentRequest(interactionId)

  if (taken?.csrfHash !== consent.csrfHash) return replay(true)

  // From here the answer can take a while (`beforeGrant`, `afterGrant`):
  // mark it as being decided, so a double-click waits for it instead of
  // seeing an error page.
  await remember({ pending: true })

  const answer = async (
    params: Readonly<Record<string, string | undefined>>,
  ): Promise<Response> => {
    const location = buildRedirect(consent.redirectUri, {
      ...params,
      state: consent.state,
      iss: options.issuer,
    })

    await remember({ location })

    return redirect(location, [dropCookie], 303)
  }

  if (!approve) {
    await releaseUpstream()
    await context.emit({
      type: "consent_declined",
      clientId: consent.clientId,
      subject: consent.subject,
    })

    return answer({
      error: "access_denied",
      error_description: "The person declined to grant access",
    })
  }

  const before = options.beforeGrant

  if (before !== undefined) {
    const outcome = await decide(() =>
      before(
        Object.freeze({
          ...frozenCopy({
            subject: consent.subject,
            client: hookClient(consent),
            scopes: [...consent.scopes],
            grantData,
          }),
          request,
        }),
      ),
    )

    if (!outcome.allowed) {
      await releaseUpstream()
      await context.emit({
        type: "authorization_refused",
        clientId: consent.clientId,
        reason: outcome.reason ?? "before_grant",
      })

      return answer({
        error: "access_denied",
        error_description: "Access was not granted",
      })
    }
  }

  const now = options.now()
  const grant: GrantRecord = {
    grantId: consent.grantId,
    clientId: consent.clientId,
    subject: consent.subject,
    scopes: consent.scopes,
    resource: consent.resource,
    createdAt: now,
    expiresAt: initialGrantExpiry(options, now),
    redirectUri: consent.redirectUri,
    ...(grantData !== undefined ? { data: grantData } : {}),
    ...(consent.allowRefresh !== undefined
      ? { allowRefresh: consent.allowRefresh }
      : {}),
    ...(consent.clientName !== undefined
      ? { clientName: consent.clientName }
      : {}),
    ...(consent.displayName !== undefined
      ? { displayName: consent.displayName }
      : {}),
    ...(consent.sealedUpstreamRefreshToken !== undefined
      ? { sealedUpstreamRefreshToken: consent.sealedUpstreamRefreshToken }
      : {}),
    ...(consent.sealedUpstreamAccessToken !== undefined &&
    consent.upstreamAccessTokenExpiresAt !== undefined
      ? {
          sealedUpstreamAccessToken: consent.sealedUpstreamAccessToken,
          upstreamAccessTokenExpiresAt: consent.upstreamAccessTokenExpiresAt,
        }
      : {}),
  }

  await store.putGrant(grant)

  const code = randomToken()

  await store.putAuthorizationCode({
    codeHash: sha256Hex(code),
    grantId: grant.grantId,
    clientId: consent.clientId,
    redirectUri: consent.redirectUri,
    codeChallenge: consent.codeChallenge,
    resource: consent.resource,
    scopes: consent.scopes,
    expiresAt: now + options.codeTtlMs,
  })

  const after = options.afterGrant

  if (after !== undefined) {
    try {
      await after(Object.freeze({ grant: grantSummary(grant) }))
    } catch (error) {
      // No grant may outlive a failed `afterGrant`: deleting the grant
      // makes its code worthless too.
      await store.deleteGrant(grant.grantId)
      await releaseUpstream()
      await context.emit({
        type: "unexpected_failure",
        where: "afterGrant",
        errorName: error instanceof Error ? error.name : typeof error,
      })

      return answer({
        error: "server_error",
        error_description: "The connection could not be completed",
      })
    }
  }

  await context.emit({
    type: "consent_approved",
    grantId: grant.grantId,
    clientId: grant.clientId,
    subject: grant.subject,
    scopes: grant.scopes,
  })

  return answer({ code })
}
