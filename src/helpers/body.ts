import { BodyTooLargeError } from "../errors/body-too-large-error.js"

/**
 * Whether the request's media type is `expected`, ignoring parameters such
 * as `charset`.
 *
 * @param request - The request.
 * @param expected - Lower-case media type.
 * @returns `true` on a match.
 * @internal
 */
export function hasContentType(request: Request, expected: string): boolean {
  const value = request.headers.get("content-type")

  if (value === null) return false

  const [type] = value.split(";")

  return (type ?? "").trim().toLowerCase() === expected
}

/**
 * Read a request body as UTF-8, stopping as soon as it passes `maxBytes`, so
 * an oversized body is never held in memory.
 *
 * @param request - The request.
 * @param maxBytes - Largest body accepted, in bytes; checked against `Content-Length` and while streaming.
 * @returns The body decoded as UTF-8; an empty string when there is no body.
 * @throws {BodyTooLargeError} When the body is larger than `maxBytes`.
 * @throws {TypeError} When the body stream yields something other than bytes.
 * @internal
 */
export async function readBody(
  request: Request,
  maxBytes: number,
): Promise<string> {
  const declared = Number(request.headers.get("content-length"))

  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new BodyTooLargeError()
  }

  if (request.body === null) return ""

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0

  for (;;) {
    const chunk = await reader.read()

    if (chunk.done) break

    const bytes: unknown = chunk.value

    // Request bodies are byte streams; anything else is not a valid body.
    if (!(bytes instanceof Uint8Array)) throw new TypeError("Body is not bytes")

    total += bytes.byteLength

    if (total > maxBytes) {
      await reader.cancel()
      throw new BodyTooLargeError()
    }

    chunks.push(bytes)
  }

  return Buffer.concat(chunks).toString("utf8")
}
