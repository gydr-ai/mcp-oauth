/**
 * Thrown by `createMcpAuth` when its options are invalid.
 *
 * @example
 * ```ts
 * import { createMcpAuth, McpAuthConfigError, type McpAuthOptions } from "@gydr-ai/mcp-oauth"
 *
 * export function tryCreate(options: McpAuthOptions) {
 *   try {
 *     return createMcpAuth(options)
 *   } catch (error) {
 *     if (error instanceof McpAuthConfigError) console.error(error.message)
 *     throw error
 *   }
 * }
 * ```
 */
export class McpAuthConfigError extends Error {
  /**
   * @param message - What is wrong with the configuration.
   */
  constructor(message: string) {
    super(message)
    this.name = "McpAuthConfigError"
  }
}
