import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"

import { SealerError } from "../errors/sealer-error.js"
import type { AesGcmSealerOptions, SecretSealer } from "../interfaces/sealer.js"

/** Length of the random initialisation vector (96 bits, as GCM recommends). */
const IV_BYTES = 12
/** Length of the authentication tag. */
const TAG_BYTES = 16
/** Allowed key ids. */
const KID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/
/** Version tag at the start of every sealed value. */
const FORMAT = "v1"

/**
 * Run synchronous crypto and report its outcome as a promise.
 *
 * @param work - Synchronous encryption or decryption; anything it throws becomes the rejection.
 * @returns Resolves with `work`'s result, or rejects with what it threw (non-errors become a `SealerError`).
 */
function attempt<T>(work: () => T): Promise<T> {
  try {
    return Promise.resolve(work())
  } catch (error) {
    return Promise.reject(
      error instanceof Error ? error : new SealerError("Sealing failed"),
    )
  }
}

/**
 * The additional data actually authenticated: format, key id, caller AAD.
 *
 * @param kid - Key id the value is (or will be) encrypted with, already checked against the allowed pattern.
 * @param aad - Caller's owner label (a grant id, optionally suffixed with `#access`); any string.
 * @returns The bytes to authenticate.
 */
function additionalData(kid: string, aad: string): Buffer {
  return Buffer.from(`${FORMAT}\u0000${kid}\u0000${aad}`, "utf8")
}

/**
 * AES-256-GCM {@link SecretSealer} with key rotation.
 *
 * Output: `v1.<kid>.<iv>.<ciphertext>.<tag>` (base64url parts). A random
 * 96-bit IV per value; the caller's AAD (the grant id) and the key id are
 * authenticated, so a sealed value moved to another grant, or relabelled with
 * another key id, fails to open.
 *
 * @param options - Keys by key id and the key id to encrypt with.
 * @returns A `SecretSealer` whose values look like `v1.<kid>.<iv>.<ciphertext>.<tag>` (base64url parts).
 * @throws {TypeError} When a key is not 32 bytes, a key id is invalid, or
 *   `currentKid` is not among the keys.
 * @example
 * ```ts
 * import { createAesGcmSealer } from "@gydr-ai/mcp-oauth"
 *
 * const sealer = createAesGcmSealer({
 *   keys: { k2026a: Buffer.from(process.env.SEALING_KEY ?? "", "base64") },
 *   currentKid: "k2026a",
 * })
 * const sealed = await sealer.seal("upstream-refresh-token", "grant-123")
 *
 * console.log(await sealer.open(sealed, "grant-123"))
 * ```
 */
export function createAesGcmSealer(options: AesGcmSealerOptions): SecretSealer {
  const keys = new Map<string, Buffer>()

  for (const [kid, key] of Object.entries(options.keys)) {
    if (!KID_PATTERN.test(kid)) {
      throw new TypeError(
        `Key id ${JSON.stringify(kid)} has characters outside A-Z a-z 0-9 _ -, or is too long`,
      )
    }

    if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
      throw new TypeError(`Key ${kid} is not 32 bytes long`)
    }

    // Copy: a caller mutating its buffer must not change our key.
    keys.set(kid, Buffer.from(key))
  }

  const current = keys.get(options.currentKid)

  if (current === undefined) {
    throw new TypeError("currentKid has no matching entry in keys")
  }

  const currentKid = options.currentKid

  return {
    seal(plaintext, aad) {
      return attempt(() => {
        const iv = randomBytes(IV_BYTES)
        const cipher = createCipheriv("aes-256-gcm", current, iv, {
          authTagLength: TAG_BYTES,
        })

        cipher.setAAD(additionalData(currentKid, aad))

        const body = Buffer.concat([
          cipher.update(plaintext, "utf8"),
          cipher.final(),
        ])

        return [
          FORMAT,
          currentKid,
          iv.toString("base64url"),
          body.toString("base64url"),
          cipher.getAuthTag().toString("base64url"),
        ].join(".")
      })
    },
    open(sealed, aad) {
      return attempt(() => {
        const parts = sealed.split(".")

        if (parts.length !== 5 || parts[0] !== FORMAT) {
          throw new SealerError("Value is not in sealed format")
        }

        const [, kid = "", ivText = "", bodyText = "", tagText = ""] = parts
        const key = keys.get(kid)

        if (key === undefined)
          throw new SealerError(
            "Value was sealed with a key that is not configured",
          )

        const iv = Buffer.from(ivText, "base64url")
        const tag = Buffer.from(tagText, "base64url")

        if (iv.byteLength !== IV_BYTES || tag.byteLength !== TAG_BYTES) {
          throw new SealerError("Value is not in sealed format")
        }

        try {
          const decipher = createDecipheriv("aes-256-gcm", key, iv, {
            authTagLength: TAG_BYTES,
          })

          decipher.setAAD(additionalData(kid, aad))
          decipher.setAuthTag(tag)

          return Buffer.concat([
            decipher.update(Buffer.from(bodyText, "base64url")),
            decipher.final(),
          ]).toString("utf8")
        } catch {
          throw new SealerError(
            "Value was altered or belongs to a different owner",
          )
        }
      })
    },
  }
}
