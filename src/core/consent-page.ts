import { CONSENT_FIELDS } from "../constants/protocol.js"
import { bindingCookieName, hostCookie } from "../helpers/cookies.js"
import { frozenCopy } from "../helpers/freeze.js"
import { parseLocales } from "../helpers/locales.js"
import {
  isLoopbackRedirectUri,
  originOf,
  redirectHostOf,
} from "../helpers/redirect-uris.js"
import { html } from "../helpers/responses.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { ConsentRequest } from "../interfaces/records.js"

/**
 * Host of a metadata-document URL, shown so people see who vouches for it.
 *
 * @param url - A metadata-document `client_id` (an `https` URL).
 * @returns The host, or an empty string.
 */
function documentHost(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return ""
  }
}

/** Optional parts of a consent page response. */
interface ConsentPageExtras {
  /** HTTP status. Default: 200. */
  readonly status?: number
  /** Problems `readConsentFields` reported, by field name. */
  readonly fieldErrors?: Readonly<Record<string, string>>
  /** Extra field values to fill the form with again. */
  readonly submitted?: Readonly<Record<string, string>>
  /** The plaintext binding cookie value, to set the consent-step cookie. */
  readonly binding?: string
  /** Other `Set-Cookie` values, such as clearing the sign-in cookie. */
  readonly setCookies?: readonly string[]
}

/**
 * Render the consent page for a stored (or about to be stored) consent
 * request and wrap it in a response with the page security headers.
 *
 * The renderer receives a deeply frozen copy of its context. The form may
 * submit (and be redirected) only to this server and the client's redirect
 * origin; inline scripts run only when listed in `scriptHashes`.
 *
 * @param context - Context supplying the renderer, paths, cookie prefix, lifetimes and script hashes.
 * @param request - The request that leads to this page; its `Accept-Language` sets `locales`.
 * @param consent - The consent request the page is for.
 * @param formToken - The plaintext one-time form token, embedded as a hidden field.
 * @param extras - Status, field errors, submitted values and cookies.
 * @returns The HTML response.
 * @throws {Error} Whatever a custom `renderConsentPage` throws.
 * @internal
 */
export function consentPageResponse(
  context: HandlerContext,
  request: Request,
  consent: ConsentRequest,
  formToken: string,
  extras: ConsentPageExtras = {},
): Response {
  const { options } = context
  const page = options.renderConsentPage(
    frozenCopy({
      clientId: consent.clientId,
      clientKind: consent.clientKind,
      redirectUri: consent.redirectUri,
      redirectHost: redirectHostOf(consent.redirectUri),
      redirectIsLoopback: isLoopbackRedirectUri(consent.redirectUri),
      scopes: consent.scopes,
      scopeDescriptions: { ...options.scopeDescriptions },
      resource: consent.resource,
      formAction: options.paths.consent,
      hiddenFields: {
        [CONSENT_FIELDS.id]: consent.id,
        [CONSENT_FIELDS.csrf]: formToken,
      },
      decisionField: CONSENT_FIELDS.decision,
      locales: parseLocales(request.headers.get("accept-language")),
      ...(consent.clientName !== undefined
        ? { clientName: consent.clientName }
        : {}),
      ...(consent.clientKind === "metadata_document"
        ? { clientHost: documentHost(consent.clientId) }
        : {}),
      ...(consent.displayName !== undefined
        ? { subjectDisplayName: consent.displayName }
        : {}),
      ...(consent.details !== undefined ? { details: consent.details } : {}),
      ...(extras.fieldErrors !== undefined
        ? { fieldErrors: extras.fieldErrors }
        : {}),
      ...(extras.submitted !== undefined
        ? { submitted: extras.submitted }
        : {}),
    }),
  )
  const target = originOf(consent.redirectUri)
  const cookies = [...(extras.setCookies ?? [])]

  if (extras.binding !== undefined) {
    cookies.push(
      hostCookie(
        bindingCookieName(options.cookiePrefix, consent.id),
        extras.binding,
        Math.ceil(options.pendingTtlMs / 1000),
      ),
    )
  }

  return html(extras.status ?? 200, page, {
    formActionOrigins: target === undefined ? [] : [target],
    setCookies: cookies,
    scriptHashes: options.scriptHashes,
  })
}
