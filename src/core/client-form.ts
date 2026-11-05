import { FORM_MEDIA_TYPE } from "../constants/protocol.js"
import { BodyTooLargeError } from "../errors/body-too-large-error.js"
import { EndpointRefusal } from "../errors/endpoint-refusal.js"
import { hasContentType, readBody } from "../helpers/body.js"
import {
  groupParams,
  type Params,
  repeatedDefined,
  single,
} from "../helpers/params.js"
import { sameResource } from "../helpers/resource.js"
import type { HandlerContext } from "../interfaces/context.js"

/** HTTP auth-scheme syntax (RFC 9110 § 11.1, `token`). */
const AUTH_SCHEME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$/

/** Parameters every client-authenticating form defines. */
const CLIENT_PARAMETERS: readonly string[] = [
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
]

/**
 * The scheme of an `Authorization` header, for echoing in a challenge.
 *
 * @param header - The header value.
 * @returns The scheme, or `Basic` when it is not a valid scheme token.
 */
function schemeOf(header: string): string {
  const scheme = header.trim().split(" ")[0] ?? ""

  return AUTH_SCHEME.test(scheme) ? scheme : "Basic"
}

/**
 * Parse the form body shared by the token and revocation endpoints and make
 * sure the caller acts as a public client.
 *
 * @param request - A POST to the token or revocation endpoint; its body is consumed.
 * @param maxBytes - Largest body accepted, in bytes (`limits.formBytes`).
 * @param defined - The parameters the endpoint defines; only these may not be repeated.
 * @returns The grouped form and the `client_id`, if sent.
 * @throws {EndpointRefusal} When the media type is wrong, the body is too large, a defined parameter is repeated, or client credentials are present.
 * @internal
 */
export async function readPublicClientForm(
  request: Request,
  maxBytes: number,
  defined: readonly string[],
): Promise<{ form: Params; clientId: string | undefined }> {
  if (!hasContentType(request, FORM_MEDIA_TYPE)) {
    throw new EndpointRefusal(
      "invalid_request",
      "Send the parameters as an application/x-www-form-urlencoded body",
    )
  }

  let form: Params

  try {
    form = groupParams(new URLSearchParams(await readBody(request, maxBytes)))
  } catch (error) {
    if (error instanceof BodyTooLargeError) {
      throw new EndpointRefusal(
        "invalid_request",
        `The body exceeds ${maxBytes} bytes`,
      )
    }

    throw error
  }

  // RFC 6749 § 3.2 forbids repeating a defined parameter; unknown ones are
  // ignored, repeated or not.
  const repeated = repeatedDefined(form, [...CLIENT_PARAMETERS, ...defined])

  if (repeated.length > 0) {
    throw new EndpointRefusal(
      "invalid_request",
      `Parameter sent more than once: ${repeated.join(", ")}`,
    )
  }

  // Credentials of any kind mean the client thinks it is confidential, which
  // no client of this server is. Saying so beats silently ignoring them.
  // RFC 6749 § 5.2: 401 with a matching `WWW-Authenticate` when the client
  // used the Authorization header; otherwise a plain 400 `invalid_client`.
  const authorization = request.headers.get("authorization")
  const refusal =
    "Clients here authenticate with PKCE alone; remove the client credentials"

  if (authorization !== null) {
    throw new EndpointRefusal(
      "invalid_client",
      refusal,
      401,
      schemeOf(authorization),
    )
  }

  if (form.has("client_secret") || form.has("client_assertion")) {
    throw new EndpointRefusal("invalid_client", refusal)
  }

  return { form, clientId: single(form, "client_id") }
}

/**
 * An explicit `resource` must be this server's (RFC 8707).
 *
 * @param context - Context supplying the configured resource URL.
 * @param form - Parsed token-endpoint form; only its optional `resource` value is read.
 * @throws {EndpointRefusal} `invalid_target` when `resource` names another resource.
 * @internal
 */
export function requireOwnResource(
  context: HandlerContext,
  form: Params,
): void {
  const resource = single(form, "resource")

  if (
    resource !== undefined &&
    !sameResource(context.options.resource, resource)
  ) {
    throw new EndpointRefusal(
      "invalid_target",
      `Tokens from this server are only for ${context.options.resource}`,
    )
  }
}
