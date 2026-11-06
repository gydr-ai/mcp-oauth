import { permits } from "../core/policy.js"
import { frozenCopy } from "../helpers/freeze.js"
import { BodyTooLargeError } from "../errors/body-too-large-error.js"
import { hasContentType, readBody } from "../helpers/body.js"
import {
  cleanClientName,
  parseClientScopes,
  parseGrantTypes,
} from "../helpers/client-fields.js"
import { redirectHostOf, redirectUriProblem } from "../helpers/redirect-uris.js"
import { json, oauthError } from "../helpers/responses.js"
import { randomToken } from "../helpers/tokens.js"
import { isRecord, isStringArray } from "../helpers/guards.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { ClientRecord } from "../interfaces/records.js"

function badMetadata(description: string): Response {
  return oauthError(400, "invalid_client_metadata", description)
}

function badRedirect(description: string): Response {
  return oauthError(400, "invalid_redirect_uri", description)
}

/**
 * `POST /register`: RFC 7591 dynamic registration of a public client. The
 * response never contains a secret; metadata this server does not use is
 * accepted and discarded.
 *
 * @param context - Context supplying the store, supported scopes, limits and `allowRegistration` hook.
 * @param request - The `POST` to the registration endpoint, with a JSON body of client metadata.
 * @returns The registration response or an OAuth error.
 * @internal
 */
export async function handleRegister(
  context: HandlerContext,
  request: Request,
): Promise<Response> {
  const { options } = context
  const { limits } = options

  if (!(await context.allowed(request, "register"))) {
    return oauthError(
      429,
      "temporarily_unavailable",
      "Registration rate exceeded; retry later",
    )
  }

  if (!hasContentType(request, "application/json")) {
    return badMetadata("Send the client metadata as application/json")
  }

  let body: unknown

  try {
    body = JSON.parse(await readBody(request, limits.registrationBytes))
  } catch (error) {
    return badMetadata(
      error instanceof BodyTooLargeError
        ? `The metadata exceeds ${limits.registrationBytes} bytes`
        : "The body is not a JSON object",
    )
  }

  if (!isRecord(body)) return badMetadata("The body is not a JSON object")

  const uris = body.redirect_uris

  if (!isStringArray(uris) || uris.length === 0) {
    return badRedirect("List at least one redirect URI in redirect_uris")
  }

  if (uris.length > limits.redirectUris) {
    return badRedirect(`Register at most ${limits.redirectUris} redirect URIs`)
  }

  for (const uri of uris) {
    const problem = redirectUriProblem(uri, limits)

    if (problem !== undefined) {
      return badRedirect(
        `Redirect URI refused (${problem}). Allowed: https URLs, or http on 127.0.0.1, [::1] or localhost`,
      )
    }
  }

  const authMethod = body.token_endpoint_auth_method

  if (authMethod !== undefined && authMethod !== "none") {
    return badMetadata(
      'This server registers public clients only; token_endpoint_auth_method must be "none"',
    )
  }

  // Omitted grant_types means authorization_code alone (RFC 7591 § 2): a
  // client has to ask for refresh tokens explicitly.
  const grantTypes = parseGrantTypes(
    body.grant_types,
    true,
    options.defaultGrantTypes,
  )

  if (grantTypes === undefined) {
    return badMetadata(
      'grant_types must include "authorization_code" and may add "refresh_token"; nothing else is offered',
    )
  }

  const responseTypes = body.response_types ?? ["code"]

  if (
    !isStringArray(responseTypes) ||
    responseTypes.length !== 1 ||
    responseTypes[0] !== "code"
  ) {
    return badMetadata('The only response type offered is "code"')
  }

  const scopes = parseClientScopes(
    body.scope,
    options.scopes,
    true,
    limits.scopeLength,
  )

  if (scopes === undefined) {
    return badMetadata(`Available scopes: ${options.scopes.join(" ")}`)
  }

  let clientName: string | undefined

  if (body.client_name !== undefined) {
    clientName = cleanClientName(body.client_name, limits.clientNameLength)

    if (clientName === undefined) {
      return badMetadata(
        `client_name needs 1 to ${limits.clientNameLength} visible characters`,
      )
    }
  }

  const policy = options.allowRegistration

  if (
    policy !== undefined &&
    !(await permits(() => policy({ metadata: frozenCopy(body), request })))
  ) {
    return oauthError(
      403,
      "invalid_client_metadata",
      "This server does not accept the registration of this client",
    )
  }

  const issuedAt = options.now()
  const redirectUris = [...new Set(uris)]
  const client: ClientRecord = {
    clientId: `client-${randomToken()}`,
    redirectUris,
    kind: "dynamic",
    createdAt: issuedAt,
    grantTypes,
    ...(scopes !== null ? { scopes } : {}),
    ...(clientName !== undefined ? { clientName } : {}),
  }

  await options.store.putClient(client)
  await context.emit({
    type: "client_registered",
    clientId: client.clientId,
    redirectHosts: [...new Set(redirectUris.map(redirectHostOf))],
    ...(clientName !== undefined ? { clientName } : {}),
  })

  return json(
    201,
    {
      client_id: client.clientId,
      client_id_issued_at: Math.floor(issuedAt / 1000),
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      ...(scopes !== null ? { scope: scopes.join(" ") } : {}),
      ...(clientName !== undefined ? { client_name: clientName } : {}),
    },
    { cors: true },
  )
}
