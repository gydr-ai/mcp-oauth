/**
 * A request whose bearer token checked out.
 *
 * @example
 * ```ts
 * import type { AuthSuccess } from "@gydr-ai/mcp-oauth"
 *
 * export function canWrite(result: AuthSuccess): boolean {
 *   return result.scopes.includes("mcp:write")
 * }
 * ```
 */
export interface AuthSuccess {
  /** Always `true`. */
  readonly ok: true
  /** The person's stable id at the identity provider. */
  readonly subject: string
  /** The grant the token belongs to. */
  readonly grantId: string
  /** The client the token was issued to. */
  readonly clientId: string
  /** Scopes the token carries. */
  readonly scopes: readonly string[]
  /**
   * Whatever `getGrantContext` returned for this grant, as a JSON-safe copy;
   * `undefined` when no such option is set.
   */
  readonly context: unknown
  /**
   * An upstream access token for acting as this person at the identity
   * provider's APIs. Cached in memory and renewed shortly before expiry, one
   * renewal per grant at a time. Rejects with `GrantInactiveError` or
   * `UpstreamTokenError`.
   */
  getUpstreamAccessToken(options?: {
    /** Skip every cache and renew at the identity provider now. */
    readonly forceRefresh?: boolean
  }): Promise<string>
}

/**
 * A request without a usable bearer token.
 *
 * @example
 * ```ts
 * import type { AuthFailure } from "@gydr-ai/mcp-oauth"
 *
 * export function reject(result: AuthFailure): Response {
 *   return result.response
 * }
 * ```
 */
export interface AuthFailure {
  /** Always `false`. */
  readonly ok: false
  /**
   * A ready response to send unchanged: 401/403 with the right
   * `WWW-Authenticate` header for token problems, or a generic 500 when
   * `getGrantContext` failed.
   */
  readonly response: Response
}

/**
 * The outcome of `McpAuth.authenticate`.
 *
 * @example
 * ```ts
 * import type { AuthResult, McpAuth } from "@gydr-ai/mcp-oauth"
 *
 * export async function guard(auth: McpAuth, request: Request): Promise<Response> {
 *   const result: AuthResult = await auth.authenticate(request)
 *
 *   return result.ok ? Response.json({ subject: result.subject }) : result.response
 * }
 * ```
 */
export type AuthResult = AuthSuccess | AuthFailure

/**
 * What `McpAuth.unauthorized` reports.
 *
 * @example
 * ```ts
 * import type { BearerError, McpAuth } from "@gydr-ai/mcp-oauth"
 *
 * export function needsWrite(auth: McpAuth, request: Request): Response {
 *   const error: BearerError = { error: "insufficient_scope", scope: ["mcp:write"] }
 *
 *   return auth.unauthorized(request, error)
 * }
 * ```
 */
export interface BearerError {
  /** RFC 6750 § 3.1 code; leave unset when the request carried no token. */
  readonly error?: "invalid_request" | "invalid_token" | "insufficient_scope"
  /** Human-readable explanation. */
  readonly description?: string
  /** Scopes needed, sent with `insufficient_scope`. Default: the default scopes. */
  readonly scope?: readonly string[]
}

/**
 * The object returned by `createMcpAuth`.
 *
 * @example
 * ```ts
 * import type { McpAuth } from "@gydr-ai/mcp-oauth"
 *
 * export async function route(auth: McpAuth, request: Request): Promise<Response> {
 *   return (await auth.handle(request)) ?? new Response("Not found", { status: 404 })
 * }
 * ```
 */
export interface McpAuth {
  /**
   * Serve the OAuth routes (metadata, registration, authorization, callback,
   * consent, token, revocation). Resolves `undefined` for any other path so
   * the host application can handle it.
   */
  handle(request: Request): Promise<Response | undefined>
  /**
   * Check the bearer token of a request to the MCP endpoint. On failure,
   * send `result.response` unchanged.
   */
  authenticate(request: Request): Promise<AuthResult>
  /**
   * Build a 401 (403 for `insufficient_scope`, 400 for `invalid_request`)
   * carrying the RFC 9728 `WWW-Authenticate` challenge.
   */
  unauthorized(request: Request, error?: BearerError): Response
  /**
   * End a grant: its tokens stop working, and its upstream refresh token is
   * revoked at the identity provider when that is supported.
   */
  revokeGrant(grantId: string): Promise<void>
  /**
   * Discard the cached upstream access token of a grant (in memory and the
   * encrypted copy on the grant) and renew it at the identity provider.
   * Rejects with `GrantInactiveError` or `UpstreamTokenError`.
   */
  renewUpstream(grantId: string): Promise<string>
  /**
   * Replace the integrator data stored on a grant (`GrantRecord.data`). The
   * data must be JSON-serializable and within `limits.grantDataBytes`.
   * Resolves `false` when the grant does not exist.
   */
  updateGrantData(grantId: string, data: unknown): Promise<boolean>
  /**
   * End every grant of one person. Needs the optional store method
   * `listGrantsBySubject`; throws `McpAuthConfigError` without it. Resolves
   * with the number of grants ended.
   */
  revokeGrantsForSubject(subject: string): Promise<number>
}
