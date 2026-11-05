import type { ClientRecord, GrantRecord } from "./records.js"

/**
 * The client as hooks see it.
 *
 * @example
 * ```ts
 * import type { HookClient } from "@gydr-ai/mcp-oauth"
 *
 * export function label(client: HookClient): string {
 *   return client.clientName ?? client.clientId
 * }
 * ```
 */
export type HookClient = Pick<ClientRecord, "clientId" | "clientName" | "kind">

/**
 * Input to the `getConsentDetails` hook.
 *
 * @example
 * ```ts
 * import type { ConsentDetailsInput } from "@gydr-ai/mcp-oauth"
 *
 * export function detailsFor(input: ConsentDetailsInput): { readonly scopes: number } {
 *   return { scopes: input.scopes.length }
 * }
 * ```
 */
export interface ConsentDetailsInput {
  /** The signed-in person's subject. */
  readonly subject: string
  /** The connecting client. */
  readonly client: HookClient
  /** Scopes the client requested. */
  readonly scopes: readonly string[]
  /** The callback request (for headers such as `Accept-Language`). */
  readonly request: Request
}

/**
 * Input to the `readConsentFields` hook.
 *
 * @example
 * ```ts
 * import type { ConsentFieldsResult, ReadConsentFieldsInput } from "@gydr-ai/mcp-oauth"
 *
 * export function readFields(input: ReadConsentFieldsInput): ConsentFieldsResult {
 *   const project = input.form.project ?? ""
 *
 *   return project === ""
 *     ? { ok: false, fieldErrors: { project: "Choose a project" } }
 *     : { ok: true, grantData: { project } }
 * }
 * ```
 */
export interface ReadConsentFieldsInput {
  /**
   * The extra form fields the consent page posted, one value per name. The
   * package's own fields are never included.
   */
  readonly form: Readonly<Record<string, string>>
  /** What `getConsentDetails` returned for this screen, if anything. */
  readonly details: unknown
  /** The signed-in person's subject. */
  readonly subject: string
  /** The connecting client. */
  readonly client: HookClient
  /** Scopes the person is approving. */
  readonly scopes: readonly string[]
}

/**
 * Result of the `readConsentFields` hook.
 *
 * @example
 * ```ts
 * import type { ConsentFieldsResult } from "@gydr-ai/mcp-oauth"
 *
 * export const accepted: ConsentFieldsResult = { ok: true, grantData: { tier: "basic" } }
 * export const retry: ConsentFieldsResult = { ok: false, fieldErrors: { tier: "Pick a tier" } }
 * ```
 */
export type ConsentFieldsResult =
  | {
      /** The fields are acceptable. */
      readonly ok: true
      /** JSON data stored on the grant as `GrantRecord.data`. */
      readonly grantData?: unknown
    }
  | {
      /** The fields need correcting; the page is shown again. */
      readonly ok: false
      /** A short message per field name, shown next to that field. */
      readonly fieldErrors: Readonly<Record<string, string>>
    }

/**
 * Input to the `beforeGrant` hook.
 *
 * @example
 * ```ts
 * import type { BeforeGrantContext, PolicyDecision } from "@gydr-ai/mcp-oauth"
 *
 * export function beforeGrant(context: BeforeGrantContext): PolicyDecision {
 *   return context.scopes.length > 0 ? true : { allow: false, reason: "no_scopes" }
 * }
 * ```
 */
export interface BeforeGrantContext {
  /** The signed-in person's subject. */
  readonly subject: string
  /** The connecting client. */
  readonly client: HookClient
  /** Scopes about to be granted. */
  readonly scopes: readonly string[]
  /** What `readConsentFields` returned as `grantData`, if anything. */
  readonly grantData: unknown
  /** The consent form submission. */
  readonly request: Request
}

/**
 * A grant as hooks and events see it: without any encrypted upstream token.
 *
 * @example
 * ```ts
 * import type { GrantSummary } from "@gydr-ai/mcp-oauth"
 *
 * export function describe(grant: GrantSummary): string {
 *   return `${grant.subject} via ${grant.clientId}`
 * }
 * ```
 */
export type GrantSummary = Omit<
  GrantRecord,
  | "sealedUpstreamRefreshToken"
  | "sealedUpstreamAccessToken"
  | "upstreamAccessTokenExpiresAt"
>

/**
 * Input to the `afterGrant` hook.
 *
 * @example
 * ```ts
 * import type { AfterGrantContext } from "@gydr-ai/mcp-oauth"
 *
 * export const connected: string[] = []
 *
 * export function afterGrant(context: AfterGrantContext): void {
 *   connected.push(context.grant.grantId)
 * }
 * ```
 */
export interface AfterGrantContext {
  /** The grant that was just stored. */
  readonly grant: GrantSummary
}

/**
 * Input to the `beforeTokenIssue` hook.
 *
 * @example
 * ```ts
 * import type { BeforeTokenIssueContext, PolicyDecision } from "@gydr-ai/mcp-oauth"
 *
 * export const suspended = new Set<string>()
 *
 * export function beforeTokenIssue(context: BeforeTokenIssueContext): PolicyDecision {
 *   return !suspended.has(context.grant.subject)
 * }
 * ```
 */
export interface BeforeTokenIssueContext {
  /** The grant tokens are about to be issued under. */
  readonly grant: GrantSummary
  /** Which token request this is. */
  readonly grantType: "authorization_code" | "refresh_token"
}
