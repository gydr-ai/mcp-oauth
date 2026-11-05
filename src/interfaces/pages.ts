import type { ErrorPageReason } from "../constants/error-pages.js"
import type { ClientKind } from "./records.js"

/**
 * Data for the consent page. A replacement renderer must:
 * - escape every value it prints with {@link escapeHtml} (or equivalent);
 * - contain a form that POSTs to `formAction`, includes each entry of
 *   `hiddenFields` unchanged, and submits a field named `decisionField` with
 *   the value `approve` to grant access (any other value declines);
 * - reference no external resources: the page is served with a
 *   Content-Security-Policy allowing only inline styles and `data:` images.
 *
 * @example
 * ```ts
 * import { type ConsentPageContext, escapeHtml } from "@gydr-ai/mcp-oauth"
 *
 * export function renderConsentPage(context: ConsentPageContext): string {
 *   const fields = Object.entries(context.hiddenFields)
 *     .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
 *     .join("")
 *
 *   return `<form method="post" action="${escapeHtml(context.formAction)}">${fields}
 * <button name="${escapeHtml(context.decisionField)}" value="approve">Allow</button>
 * <button name="${escapeHtml(context.decisionField)}" value="deny">Deny</button></form>`
 * }
 * ```
 */
export interface ConsentPageContext {
  /** Name the client gave itself, if any. Not verified. */
  readonly clientName?: string
  /** The client id. */
  readonly clientId: string
  /** How the client made itself known. */
  readonly clientKind: ClientKind
  /**
   * For a metadata-document client: the HTTPS host its metadata was served
   * from. Otherwise `undefined`.
   */
  readonly clientHost?: string
  /** Address the result will be delivered to. */
  readonly redirectUri: string
  /** Host part of `redirectUri` (without the port for loopback). */
  readonly redirectHost: string
  /** `redirectUri` is an `http` loopback address, i.e. a local program. */
  readonly redirectIsLoopback: boolean
  /** Scopes being requested. */
  readonly scopes: readonly string[]
  /** Plain-language description per scope, from the `scopeDescriptions` option. */
  readonly scopeDescriptions: Readonly<Record<string, string>>
  /** How the identity provider names the signed-in person, if it does. */
  readonly subjectDisplayName?: string
  /** The resource access is requested for. */
  readonly resource: string
  /** Where the form posts to. */
  readonly formAction: string
  /** Hidden fields the form must post back unchanged. */
  readonly hiddenFields: Readonly<Record<string, string>>
  /** Name of the field carrying `approve` or `deny`. */
  readonly decisionField: string
  /** Languages the browser prefers, most preferred first, from `Accept-Language`. */
  readonly locales: readonly string[]
  /** What `getConsentDetails` returned (JSON data), if that hook is set. */
  readonly details?: unknown
  /**
   * Problems `readConsentFields` reported with the extra fields, by field
   * name, when the page is shown again after a submission.
   */
  readonly fieldErrors?: Readonly<Record<string, string>>
  /** Extra field values from that submission, to fill the form again. */
  readonly submitted?: Readonly<Record<string, string>>
}

/**
 * Data for an error page. Contains nothing secret.
 *
 * @example
 * ```ts
 * import { type ErrorPageContext, escapeHtml } from "@gydr-ai/mcp-oauth"
 *
 * export function renderErrorPage(context: ErrorPageContext): string {
 *   return `<h1>${escapeHtml(context.title)}</h1><p>${escapeHtml(context.message)}</p>`
 * }
 * ```
 */
export interface ErrorPageContext {
  /** HTTP status of the page. */
  readonly status: number
  /** Stable reason code; switch on it for your own wording. */
  readonly reason: ErrorPageReason
  /** Built-in English heading. */
  readonly title: string
  /** Built-in English explanation for the person. */
  readonly message: string
  /** Protocol detail for developers, such as which parameter was wrong. */
  readonly detail?: string
  /** Reason code a policy hook gave for its refusal, if any. */
  readonly policyReason?: string
  /** Languages the browser prefers, most preferred first, from `Accept-Language`. */
  readonly locales: readonly string[]
}
