/**
 * The grant behind a token has been removed or has expired, so no upstream
 * token can be produced for it.
 *
 * @example
 * ```ts
 * import { type AuthSuccess, type McpAuth, GrantInactiveError } from "@gydr-ai/mcp-oauth"
 *
 * export async function upstreamOrChallenge(
 *   auth: McpAuth,
 *   request: Request,
 *   result: AuthSuccess,
 * ): Promise<string | Response> {
 *   try {
 *     return await result.getUpstreamAccessToken()
 *   } catch (error) {
 *     if (error instanceof GrantInactiveError) return auth.unauthorized(request)
 *     throw error
 *   }
 * }
 * ```
 */
export class GrantInactiveError extends Error {
  /** Creates the error with a fixed message. */
  constructor() {
    super("The grant this token belonged to has been removed")
    this.name = "GrantInactiveError"
  }
}
