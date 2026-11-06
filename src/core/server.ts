import { McpAuthConfigError } from "../errors/mcp-auth-config-error.js"
import { jsonCopy } from "../helpers/json.js"
import {
  methodNotAllowed,
  preflight,
  withTransportSecurity,
} from "../helpers/responses.js"
import type { McpAuth } from "../interfaces/auth.js"
import type { McpAuthOptions } from "../interfaces/options.js"
import type { RevokeGrant } from "../interfaces/routes.js"
import { authenticateRequest, bearerChallenge } from "./authenticate.js"
import { createContext } from "./context.js"
import { revokeGrantById } from "./grants.js"
import { defaultConsentPage, defaultErrorPage } from "./pages.js"
import { resolveOptions } from "./resolve-options.js"
import { buildRoutes } from "./router.js"
import { UpstreamTokenCache } from "./upstream-tokens.js"

/**
 * Create the authorization server and resource-server guard for one MCP
 * endpoint.
 *
 * Every option that can be customised is checked here, once; extensions can
 * only add checks, enrich data or observe events, never relax a protocol or
 * security rule.
 *
 * @param options - Configuration; see {@link McpAuthOptions}.
 * @returns The request handler and guard.
 * @throws {McpAuthConfigError} When an option is invalid.
 * @example
 * ```ts
 * import { randomBytes } from "node:crypto"
 * import {
 *   createAesGcmSealer,
 *   createMcpAuth,
 *   createMemoryStore,
 *   createOidcProvider,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const auth = createMcpAuth({
 *   issuer: "https://mcp.example.com",
 *   resource: "https://mcp.example.com/mcp",
 *   identityProvider: createOidcProvider({
 *     issuer: "https://login.example.com",
 *     clientId: "mcp-gateway",
 *     scopes: ["openid", "offline_access"],
 *     redirectUri: "https://mcp.example.com/callback",
 *   }),
 *   store: createMemoryStore(),
 *   sealer: createAesGcmSealer({ keys: { k1: randomBytes(32) }, currentKid: "k1" }),
 * })
 *
 * export async function serve(request: Request): Promise<Response> {
 *   const oauth = await auth.handle(request)
 *
 *   if (oauth) return oauth
 *
 *   const result = await auth.authenticate(request)
 *
 *   if (!result.ok) return result.response
 *
 *   return Response.json({ hello: result.subject })
 * }
 * ```
 */
export function createMcpAuth(options: McpAuthOptions): McpAuth {
  const resolved = resolveOptions(options, {
    consent: defaultConsentPage,
    error: defaultErrorPage,
  })
  const context = createContext(resolved)
  const upstream = new UpstreamTokenCache(context)
  const revoke: RevokeGrant = (grantId, reason) =>
    revokeGrantById(context, grantId, reason, (id) => {
      upstream.forget(id)
    })
  const routes = buildRoutes(context, revoke)
  const secured = (response: Response) =>
    withTransportSecurity(response, resolved.strictTransportSecurity)
  const route = async (request: Request) => {
    const entry = routes.get(new URL(request.url).pathname)

    if (entry === undefined) return undefined

    if (request.method === "OPTIONS" && entry.cors) {
      return preflight([...entry.methods, "OPTIONS"].join(", "))
    }

    if (!entry.methods.includes(request.method)) {
      return methodNotAllowed(entry.methods.join(", "))
    }

    return entry.run(request)
  }

  return {
    async handle(request) {
      const response = await route(request)

      return response === undefined ? undefined : secured(response)
    },
    async authenticate(request) {
      const result = await authenticateRequest(
        context,
        request,
        (grantId, forceRefresh) => upstream.get(grantId, forceRefresh),
      )

      if (!result.ok) secured(result.response)

      return result
    },
    unauthorized(_request, error) {
      return secured(bearerChallenge(context, error))
    },
    revokeGrant(grantId) {
      return revoke(grantId, "revoke_grant_call")
    },
    renewUpstream(grantId) {
      return upstream.get(grantId, true)
    },
    async updateGrantData(grantId, data) {
      const copy = jsonCopy(
        data,
        resolved.limits.grantDataBytes,
        "updateGrantData",
      )

      return resolved.store.updateGrant(grantId, { data: copy })
    },
    async revokeGrantsForSubject(subject) {
      const { store } = resolved

      if (store.listGrantsBySubject === undefined) {
        throw new McpAuthConfigError(
          "revokeGrantsForSubject needs a store with listGrantsBySubject",
        )
      }

      const grants = await store.listGrantsBySubject(subject)
      let ended = 0

      for (const grant of grants) {
        // Never trust the store's filter to end someone else's grant.
        if (grant.subject !== subject) continue

        await revoke(grant.grantId, "revoke_subject_call")
        ended += 1
      }

      return ended
    },
  }
}
