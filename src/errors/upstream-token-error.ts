/**
 * No upstream access token could be obtained for a grant. The message never
 * contains a token.
 *
 * @example
 * ```ts
 * import { type AuthSuccess, UpstreamTokenError } from "@gydr-ai/mcp-oauth"
 *
 * export async function upstreamToken(result: AuthSuccess): Promise<string | undefined> {
 *   try {
 *     return await result.getUpstreamAccessToken()
 *   } catch (error) {
 *     if (error instanceof UpstreamTokenError) return undefined
 *     throw error
 *   }
 * }
 * ```
 */
export class UpstreamTokenError extends Error {
  /**
   * @param message - What failed.
   * @param options - Standard error options, such as `cause`.
   * @param options.cause - The error that caused the failure, such as the provider's rejection.
   */
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = "UpstreamTokenError"
  }
}
