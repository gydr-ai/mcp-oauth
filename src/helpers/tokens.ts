import { createHash, randomBytes, timingSafeEqual } from "node:crypto"

/** Entropy of every token, code, identifier and cookie value we mint. */
const SECRET_BYTES = 32

/** Length of a base64url-encoded SHA-256 digest or of 32 random bytes. */
const ENCODED_32_BYTES = 43

/**
 * A new unguessable value: 256 random bits, base64url without padding.
 *
 * @returns 43 base64url characters.
 * @internal
 */
export function randomToken(): string {
  return randomBytes(SECRET_BYTES).toString("base64url")
}

/**
 * Hex SHA-256 of a UTF-8 string. Tokens and codes are stored only like this.
 *
 * @param value - Any UTF-8 string, typically an opaque token, code or cookie value.
 * @returns 64 lower-case hexadecimal characters.
 * @internal
 */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex")
}

/**
 * The S256 code challenge for a verifier (RFC 7636 § 4.2).
 *
 * @param verifier - An RFC 7636 code verifier (ASCII).
 * @returns The base64url challenge.
 * @internal
 */
export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url")
}

/**
 * Compare two strings without leaking where they differ.
 *
 * @param a - First value, typically a freshly computed hash.
 * @param b - Second value, typically the stored hash.
 * @returns `true` when equal.
 * @internal
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8")
  const right = Buffer.from(b, "utf8")

  return left.length === right.length && timingSafeEqual(left, right)
}

const BASE64URL_EXTRA = "-_"
const VERIFIER_EXTRA = "-._~"

function charsetCheck(extra: string) {
  return (text: string): boolean => {
    for (let i = 0; i < text.length; i += 1) {
      const c = text.charCodeAt(i)
      const alphanumeric =
        (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122)

      if (!alphanumeric && !extra.includes(text.charAt(i))) return false
    }

    return true
  }
}

const onlyBase64Url = charsetCheck(BASE64URL_EXTRA)
const onlyVerifierChars = charsetCheck(VERIFIER_EXTRA)

/**
 * A code verifier as RFC 7636 § 4.1 defines it: 43 to 128 unreserved characters.
 *
 * @param verifier - The raw `code_verifier` form value.
 * @returns `true` when well formed.
 * @internal
 */
export function isWellFormedVerifier(verifier: string): boolean {
  return (
    verifier.length >= 43 &&
    verifier.length <= 128 &&
    onlyVerifierChars(verifier)
  )
}

/**
 * An S256 challenge: a SHA-256 digest in base64url, 43 characters.
 *
 * @param challenge - The raw `code_challenge` query value.
 * @returns `true` when well formed.
 * @internal
 */
export function isWellFormedChallenge(challenge: string): boolean {
  return challenge.length === ENCODED_32_BYTES && onlyBase64Url(challenge)
}

/**
 * Shaped like a token minted by {@link randomToken}.
 *
 * @param value - A bearer value, code or refresh token as sent by a client, unvalidated.
 * @returns `true` when well formed.
 * @internal
 */
export function isOpaqueToken(value: string): boolean {
  return value.length === ENCODED_32_BYTES && onlyBase64Url(value)
}

/**
 * Does `verifier` hash to `challenge`? Malformed verifiers never do.
 *
 * @param verifier - The raw `code_verifier` form value; malformed values never match.
 * @param challenge - The S256 challenge stored with the authorization code.
 * @returns `true` on a match.
 * @internal
 */
export function pkceMatches(verifier: string, challenge: string): boolean {
  return (
    isWellFormedVerifier(verifier) &&
    constantTimeEqual(pkceChallenge(verifier), challenge)
  )
}
