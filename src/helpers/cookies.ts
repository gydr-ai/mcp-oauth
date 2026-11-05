import { sha256Hex } from "./tokens.js"

/**
 * Read one cookie from the `Cookie` header; the first occurrence wins.
 *
 * @param request - The request.
 * @param name - Cookie name.
 * @returns The cookie value without surrounding spaces, or `undefined` when absent.
 * @internal
 */
export function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie")

  if (header === null) return undefined

  for (const part of header.split(";")) {
    const index = part.indexOf("=")

    if (index !== -1 && part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim()
    }
  }

  return undefined
}

/**
 * A `Set-Cookie` value for a `__Host-` cookie: `Secure`, `HttpOnly`,
 * `SameSite=Lax`, `Path=/` and no `Domain`, so it is bound to this exact host.
 *
 * @param name - Cookie name.
 * @param value - Cookie value.
 * @param maxAgeSeconds - Lifetime.
 * @returns The header value.
 * @internal
 */
export function hostCookie(
  name: string,
  value: string,
  maxAgeSeconds: number,
): string {
  return `${name}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`
}

/**
 * A `Set-Cookie` value that deletes a `__Host-` cookie.
 *
 * @param name - Cookie name.
 * @returns The header value.
 * @internal
 */
export function clearHostCookie(name: string): string {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
}

/**
 * Cookie name for one flow: the configured prefix plus a tag derived from
 * the flow id. Separate names let a browser run several authorizations side
 * by side.
 *
 * @param prefix - Configured cookie name prefix.
 * @param flowId - The flow or consent id.
 * @returns The cookie name.
 * @internal
 */
export function bindingCookieName(prefix: string, flowId: string): string {
  return prefix + sha256Hex(`binding:${flowId}`).slice(0, 20)
}
