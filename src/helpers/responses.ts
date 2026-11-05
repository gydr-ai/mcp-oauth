import { METADATA_MAX_AGE_SECONDS } from "../constants/defaults.js"
import { JSON_MEDIA_TYPE } from "../constants/protocol.js"

/** Caching headers every OAuth response carries (RFC 6749 § 5.1). */
const NO_STORE: Readonly<Record<string, string>> = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
}

/** Open CORS for the cookie-free endpoints that browser-based clients call. */
const CORS: Readonly<Record<string, string>> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Expose-Headers": "WWW-Authenticate",
}

/** Options for {@link json}. */
interface JsonOptions {
  /** Add open CORS headers. Default: `false`. */
  readonly cors?: boolean
  /** Allow shared caches to keep the response briefly. Default: `false`. */
  readonly cacheable?: boolean
  /** Extra headers. */
  readonly headers?: Readonly<Record<string, string>>
}

/**
 * Build a JSON response, not cacheable unless asked.
 *
 * @param status - HTTP status.
 * @param body - Value to serialize.
 * @param options - CORS, caching and extra headers.
 * @returns The response with `Content-Type: application/json`.
 * @internal
 */
export function json(
  status: number,
  body: unknown,
  options: JsonOptions = {},
): Response {
  const headers = new Headers({
    "Content-Type": JSON_MEDIA_TYPE,
    ...(options.cacheable
      ? { "Cache-Control": `public, max-age=${METADATA_MAX_AGE_SECONDS}` }
      : NO_STORE),
    ...(options.cors ? CORS : {}),
    ...options.headers,
  })

  return new Response(JSON.stringify(body), { status, headers })
}

/**
 * Build an OAuth error response (RFC 6749 § 5.2).
 *
 * @param status - HTTP status.
 * @param error - OAuth error code.
 * @param description - Optional `error_description`.
 * @param challenge - Optional `WWW-Authenticate` value.
 * @returns A JSON response with open CORS and `Cache-Control: no-store`.
 * @internal
 */
export function oauthError(
  status: number,
  error: string,
  description?: string,
  challenge?: string,
): Response {
  return json(
    status,
    description === undefined
      ? { error }
      : { error, error_description: description },
    {
      cors: true,
      ...(challenge !== undefined
        ? { headers: { "WWW-Authenticate": challenge } }
        : {}),
    },
  )
}

/**
 * Answer a CORS preflight for a browser-callable endpoint.
 *
 * @param methods - Comma-separated allowed methods.
 * @returns A 204 response.
 * @internal
 */
export function preflight(methods: string): Response {
  return new Response(null, {
    status: 204,
    headers: {
      ...CORS,
      "Access-Control-Allow-Methods": methods,
      "Access-Control-Allow-Headers":
        "Authorization, Content-Type, MCP-Protocol-Version",
      "Access-Control-Max-Age": "600",
    },
  })
}

/**
 * Answer 405 with the methods the route does accept.
 *
 * @param allow - Comma-separated allowed methods.
 * @returns A 405 response.
 * @internal
 */
export function methodNotAllowed(allow: string): Response {
  return new Response(null, {
    status: 405,
    headers: { Allow: allow, ...NO_STORE },
  })
}

/**
 * Security headers for every HTML page: a strict Content-Security-Policy
 * (inline styles only, no scripts, forms only to this server and the listed
 * origins, no framing), plus no caching and no referrer.
 *
 * @param formActionOrigins - Extra origins a form may submit or redirect to.
 * @param scriptHashes - Inline script hashes (`sha256-…`) the page may run.
 * @returns Header names and values for the page response.
 * @internal
 */
export function pageHeaders(
  formActionOrigins: readonly string[] = [],
  scriptHashes: readonly string[] = [],
): Record<string, string> {
  const formAction = ["'self'", ...formActionOrigins].join(" ")
  const scripts =
    scriptHashes.length === 0
      ? ""
      : ` script-src ${scriptHashes.map((h) => `'${h}'`).join(" ")};`

  return {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": `default-src 'none';${scripts} style-src 'unsafe-inline'; img-src data:; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    ...NO_STORE,
  }
}

/** Options for {@link html}. */
interface HtmlOptions {
  /** Extra origins the page's form may submit or redirect to. */
  readonly formActionOrigins?: readonly string[]
  /** `Set-Cookie` header values to add. */
  readonly setCookies?: readonly string[]
  /** Inline script hashes the page may run. */
  readonly scriptHashes?: readonly string[]
}

/**
 * Build an HTML page response with the page security headers.
 *
 * @param status - HTTP status.
 * @param body - The complete HTML document.
 * @param options - Form origins and cookies.
 * @returns The HTML response.
 * @internal
 */
export function html(
  status: number,
  body: string,
  options: HtmlOptions = {},
): Response {
  const headers = new Headers(
    pageHeaders(options.formActionOrigins, options.scriptHashes),
  )

  for (const cookie of options.setCookies ?? []) {
    headers.append("Set-Cookie", cookie)
  }

  return new Response(body, { status, headers })
}

/**
 * Build a redirect that is never cached and sends no referrer.
 *
 * @param location - Target URL.
 * @param setCookies - `Set-Cookie` header values to add.
 * @param status - 302, or 303 after a form POST so the browser follows with
 *   GET (OAuth 2.1 § 7.5.4).
 * @returns A redirect response.
 * @internal
 */
export function redirect(
  location: string,
  setCookies: readonly string[] = [],
  status: 302 | 303 = 302,
): Response {
  const headers = new Headers({
    Location: location,
    "Referrer-Policy": "no-referrer",
    ...NO_STORE,
  })

  for (const cookie of setCookies) headers.append("Set-Cookie", cookie)

  return new Response(null, { status, headers })
}
