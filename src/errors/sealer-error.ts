/**
 * A sealed value could not be opened: it is malformed, was altered, belongs
 * to another owner, or was encrypted with a key that is not configured.
 *
 * @example
 * ```ts
 * import { type SecretSealer, SealerError } from "@gydr-ai/mcp-oauth"
 *
 * export async function openOrNothing(sealer: SecretSealer, value: string, grantId: string) {
 *   try {
 *     return await sealer.open(value, grantId)
 *   } catch (error) {
 *     if (error instanceof SealerError) return undefined
 *     throw error
 *   }
 * }
 * ```
 */
export class SealerError extends Error {
  /**
   * @param message - Why the value could not be opened.
   */
  constructor(message: string) {
    super(message)
    this.name = "SealerError"
  }
}
