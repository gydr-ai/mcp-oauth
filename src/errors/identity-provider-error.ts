/**
 * A call to the identity provider failed. The message never contains a token.
 *
 * @example
 * ```ts
 * import { type IdentityProvider, IdentityProviderError } from "@gydr-ai/mcp-oauth"
 *
 * export async function renew(provider: IdentityProvider, refreshToken: string) {
 *   try {
 *     return await provider.refresh(refreshToken)
 *   } catch (error) {
 *     if (error instanceof IdentityProviderError) console.warn(error.code)
 *     throw error
 *   }
 * }
 * ```
 */
export class IdentityProviderError extends Error {
  /** The provider's OAuth `error` code, when it sent one. */
  readonly code: string | undefined

  /**
   * @param message - What failed.
   * @param code - The provider's OAuth `error` code, if any.
   * @param options - Standard error options, such as `cause`.
   * @param options.cause - The underlying network or verification error.
   */
  constructor(message: string, code?: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = "IdentityProviderError"
    this.code = code
  }
}
