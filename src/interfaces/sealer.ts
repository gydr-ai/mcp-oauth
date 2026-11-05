/**
 * Encrypts secrets at rest. `aad` (additional authenticated data) binds the
 * ciphertext to its owner: opening it with any other `aad` must fail.
 * `createAesGcmSealer` implements it; one backed by a key-management service
 * or HSM works as well.
 *
 * @example
 * ```ts
 * import { randomBytes } from "node:crypto"
 * import type { AesGcmSealerOptions, SecretSealer } from "@gydr-ai/mcp-oauth"
 * import { createAesGcmSealer } from "@gydr-ai/mcp-oauth"
 *
 * declare const kms: {
 *   encrypt(plaintext: string, context: string): Promise<string>
 *   decrypt(ciphertext: string, context: string): Promise<string>
 * }
 *
 * // A sealer backed by a key-management service: bind `aad` as the context.
 * export const kmsSealer: SecretSealer = {
 *   seal: (plaintext, aad) => kms.encrypt(plaintext, aad),
 *   open: (sealed, aad) => kms.decrypt(sealed, aad),
 * }
 *
 * const options: AesGcmSealerOptions = { keys: { k1: randomBytes(32) }, currentKid: "k1" }
 * export const localSealer = createAesGcmSealer(options)
 * ```
 */
export interface SecretSealer {
  /** Encrypt `plaintext` for the owner named by `aad`. */
  seal(plaintext: string, aad: string): Promise<string>
  /** Decrypt a value; reject when it was altered or `aad` differs. */
  open(sealed: string, aad: string): Promise<string>
}

/**
 * Options for `createAesGcmSealer`.
 *
 * @example
 * ```ts
 * import { randomBytes } from "node:crypto"
 * import type { AesGcmSealerOptions, SecretSealer } from "@gydr-ai/mcp-oauth"
 * import { createAesGcmSealer } from "@gydr-ai/mcp-oauth"
 *
 * declare const kms: {
 *   encrypt(plaintext: string, context: string): Promise<string>
 *   decrypt(ciphertext: string, context: string): Promise<string>
 * }
 *
 * // A sealer backed by a key-management service: bind `aad` as the context.
 * export const kmsSealer: SecretSealer = {
 *   seal: (plaintext, aad) => kms.encrypt(plaintext, aad),
 *   open: (sealed, aad) => kms.decrypt(sealed, aad),
 * }
 *
 * const options: AesGcmSealerOptions = { keys: { k1: randomBytes(32) }, currentKid: "k1" }
 * export const localSealer = createAesGcmSealer(options)
 * ```
 */
export interface AesGcmSealerOptions {
  /**
   * Keys by key id, each 32 random bytes (AES-256). Keep retired keys here
   * until nothing encrypted with them remains. Key ids: 1–32 characters of
   * `A-Z a-z 0-9 _ -`.
   */
  readonly keys: Readonly<Record<string, Uint8Array>>
  /** The key id new values are encrypted with. */
  readonly currentKid: string
}
