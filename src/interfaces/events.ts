import type { GrantSummary } from "./consent.js"

/**
 * What the server reports through the optional `onEvent` hook.
 *
 * Events are safe to log as they are: none contains a token, authorization
 * code, PKCE verifier, cookie or form-token value, client `state`, or
 * anything obtained from the identity provider other than the subject and
 * (in `grant_revoked`) the display name. Client ids, client names and
 * subjects are included so that connections can be audited; `grant_revoked`
 * also carries the grant's integrator `data`.
 */

/**
 * The endpoint a rate-limit decision is made for.
 *
 * @example
 * ```ts
 * import type { RateLimitScope } from "@gydr-ai/mcp-oauth"
 *
 * const perMinute: Record<RateLimitScope, number> = {
 *   register: 2, authorize: 30, callback: 30, consent: 30, token: 120, revoke: 60,
 * }
 *
 * export function limitFor(scope: RateLimitScope): number {
 *   return perMinute[scope]
 * }
 * ```
 */
export type RateLimitScope =
  "register" | "authorize" | "callback" | "consent" | "token" | "revoke"

/**
 * What ended a grant.
 *
 * @example
 * ```ts
 * import type { GrantRevokeReason } from "@gydr-ai/mcp-oauth"
 *
 * export const alarming: readonly GrantRevokeReason[] = [
 *   "refresh_token_replay",
 *   "authorization_code_replay",
 * ]
 * ```
 */
export type GrantRevokeReason =
  /** `McpAuth.revokeGrant` was called. */
  | "revoke_grant_call"
  /** A refresh token of the grant was sent to the revocation endpoint. */
  | "revocation_request"
  /** A spent refresh token came back outside the retry window. */
  | "refresh_token_replay"
  /** An authorization code was presented a second time. */
  | "authorization_code_replay"
  /** The code was presented with a different client, URI, resource or verifier. */
  | "authorization_code_mismatch"
  /** The code was presented after it expired. */
  | "authorization_code_expired"
  /** `McpAuth.revokeGrantsForSubject` was called. */
  | "revoke_subject_call"

/**
 * Union of all events, discriminated by `type`.
 *
 * @example
 * ```ts
 * import type { McpAuthEvent } from "@gydr-ai/mcp-oauth"
 *
 * export function log(event: McpAuthEvent): void {
 *   switch (event.type) {
 *     case "refresh_token_replayed":
 *     case "authorization_code_replayed":
 *       console.warn("possible token theft", event.grantId)
 *       break
 *     default:
 *       console.info(event.type)
 *   }
 * }
 * ```
 */
export type McpAuthEvent =
  | {
      readonly type: "client_registered"
      readonly clientId: string
      readonly clientName?: string
      readonly redirectHosts: readonly string[]
    }
  | {
      readonly type: "client_metadata_refused"
      readonly host: string
      readonly reason: string
    }
  | {
      readonly type: "authorization_started"
      readonly clientId: string
      readonly scopes: readonly string[]
    }
  | {
      readonly type: "authorization_refused"
      readonly clientId?: string
      readonly reason: string
    }
  | {
      readonly type: "identity_provider_error"
      readonly clientId: string
      readonly reason: string
    }
  | {
      readonly type: "flow_binding_mismatch"
      readonly step: "callback" | "consent"
    }
  | {
      readonly type: "consent_approved"
      readonly grantId: string
      readonly clientId: string
      readonly subject: string
      readonly scopes: readonly string[]
    }
  | {
      readonly type: "consent_declined"
      readonly clientId: string
      readonly subject: string
    }
  | {
      readonly type: "token_issued"
      readonly grantId: string
      readonly clientId: string
      readonly subject: string
      readonly grantType: "authorization_code" | "refresh_token"
    }
  | {
      readonly type: "token_request_refused"
      readonly clientId?: string
      readonly error: string
      readonly reason: string
    }
  | {
      readonly type: "refresh_token_replayed"
      readonly grantId: string
      readonly clientId: string
    }
  | {
      readonly type: "authorization_code_replayed"
      readonly grantId: string
      readonly clientId: string
    }
  | {
      readonly type: "grant_revoked"
      readonly grantId: string
      readonly reason: GrantRevokeReason
      /**
       * The grant as it was, without its encrypted upstream tokens. Emitted
       * before the grant is deleted.
       */
      readonly grant: GrantSummary
    }
  | {
      readonly type: "upstream_token_refresh_failed"
      readonly grantId: string
      readonly reason: string
    }
  | {
      readonly type: "request_throttled"
      readonly scope: RateLimitScope
    }
  | {
      /** `getGrantContext` failed; the request was answered with a 500. */
      readonly type: "grant_context_failed"
      readonly grantId: string
    }
  | {
      readonly type: "unexpected_failure"
      readonly where: string
      readonly errorName: string
    }

/**
 * Receives events. Whatever it throws or rejects with is ignored.
 *
 * @example
 * ```ts
 * import type { McpAuthEventHandler } from "@gydr-ai/mcp-oauth"
 *
 * export const onEvent: McpAuthEventHandler = (event) => {
 *   console.info(JSON.stringify(event))
 * }
 * ```
 */
export type McpAuthEventHandler = (event: McpAuthEvent) => void | Promise<void>
