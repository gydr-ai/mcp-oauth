import { handleAuthorize } from "../handlers/authorize.js"
import { handleCallback } from "../handlers/callback.js"
import { handleConsent } from "../handlers/consent.js"
import { handleRegister } from "../handlers/register.js"
import { handleRevoke } from "../handlers/revoke.js"
import { handleToken } from "../handlers/token.js"
import { json, oauthError } from "../helpers/responses.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { RevokeGrant, RouteEntry } from "../interfaces/routes.js"
import {
  authorizationServerMetadata,
  protectedResourceMetadata,
} from "./metadata.js"

/**
 * Run a handler, turning any unexpected error into a generic response and
 * an `unexpected_failure` event, so no internal detail reaches the client.
 *
 * @param context - Context used to emit `unexpected_failure` when the handler throws.
 * @param where - Handler name for the event.
 * @param run - The handler.
 * @param fail - Builds the generic response.
 * @returns The handler's response, or the generic one.
 */
async function guarded(
  context: HandlerContext,
  where: string,
  run: () => Promise<Response>,
  fail: () => Response,
): Promise<Response> {
  try {
    return await run()
  } catch (error) {
    await context.emit({
      type: "unexpected_failure",
      where,
      errorName: error instanceof Error ? error.name : "unknown",
    })

    return fail()
  }
}

/**
 * Build the route table: metadata documents, registration (when enabled),
 * authorization, callback, consent, token and revocation. When two paths
 * coincide, the first entry wins.
 *
 * @param context - Context with the checked options; paths, enabled endpoints and metadata come from it.
 * @param revoke - Ends a grant with a reason; passed to the token and revocation handlers for replay and revocation.
 * @returns Routes by exact path.
 * @internal
 */
export function buildRoutes(
  context: HandlerContext,
  revoke: RevokeGrant,
): ReadonlyMap<string, RouteEntry> {
  const { options } = context
  const serverError = () =>
    oauthError(
      500,
      "server_error",
      "An unexpected condition stopped the request",
    )
  const pageError = (request: Request) =>
    context.errorPage(request, "server_error")
  const routes = new Map<string, RouteEntry>()
  const add = (path: string, entry: RouteEntry) => {
    if (!routes.has(path)) routes.set(path, entry)
  }
  const document = (body: Record<string, unknown>): RouteEntry => ({
    methods: ["GET"],
    cors: true,
    run: () =>
      Promise.resolve(json(200, body, { cors: true, cacheable: true })),
  })

  for (const path of options.resourceMetadataPaths) {
    add(path, document(protectedResourceMetadata(options)))
  }

  for (const path of options.authorizationServerMetadataPaths) {
    add(path, document(authorizationServerMetadata(options)))
  }

  if (options.dynamicClientRegistration) {
    add(options.paths.register, {
      methods: ["POST"],
      cors: true,
      run: (request) =>
        guarded(
          context,
          "register",
          () => handleRegister(context, request),
          serverError,
        ),
    })
  }

  add(options.paths.authorize, {
    methods: ["GET"],
    cors: false,
    run: (request) =>
      guarded(
        context,
        "authorize",
        () => handleAuthorize(context, request),
        () => pageError(request),
      ),
  })
  add(options.paths.callback, {
    methods: ["GET"],
    cors: false,
    run: (request) =>
      guarded(
        context,
        "callback",
        () => handleCallback(context, request),
        () => pageError(request),
      ),
  })
  add(options.paths.consent, {
    methods: ["POST"],
    cors: false,
    run: (request) =>
      guarded(
        context,
        "consent",
        () => handleConsent(context, request),
        () => pageError(request),
      ),
  })
  add(options.paths.token, {
    methods: ["POST"],
    cors: true,
    run: (request) =>
      guarded(
        context,
        "token",
        () => handleToken(context, request, revoke),
        serverError,
      ),
  })
  add(options.paths.revoke, {
    methods: ["POST"],
    cors: true,
    run: (request) =>
      guarded(
        context,
        "revoke",
        () => handleRevoke(context, request, revoke),
        serverError,
      ),
  })

  return routes
}
