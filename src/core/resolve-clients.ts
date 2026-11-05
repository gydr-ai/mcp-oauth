import { McpAuthConfigError } from "../errors/mcp-auth-config-error.js"
import { freezeDeep } from "../helpers/freeze.js"
import {
  cleanClientName,
  isMetadataDocumentClientId,
  parseGrantTypes,
} from "../helpers/client-fields.js"
import { redirectUriProblem } from "../helpers/redirect-uris.js"
import { hasHiddenCharacters } from "../helpers/text.js"
import type { Limits } from "../interfaces/options.js"
import type { StaticClient } from "../interfaces/policy.js"
import type { ClientRecord } from "../interfaces/records.js"

/**
 * Check scope descriptions: each key must be a supported scope and each text
 * a visible string of at most 200 characters.
 *
 * @param scopes - The supported scopes after defaults were applied; every description key must be one of them.
 * @param descriptions - Configured descriptions.
 * @returns The descriptions.
 * @throws {McpAuthConfigError} When a key or text is invalid.
 * @internal
 */
export function resolveScopeDescriptions(
  scopes: readonly string[],
  descriptions: Readonly<Record<string, string>> = {},
): Readonly<Record<string, string>> {
  for (const [scope, text] of Object.entries(descriptions)) {
    if (!scopes.includes(scope)) {
      throw new McpAuthConfigError(
        `scopeDescriptions names ${scope}, which is not in scopes`,
      )
    }

    if (text.trim() === "" || text.length > 200 || hasHiddenCharacters(text)) {
      throw new McpAuthConfigError(
        `scopeDescriptions.${scope} must be 1 to 200 visible characters`,
      )
    }
  }

  // A null-prototype copy, so lookups never reach Object.prototype.
  const own: Record<string, string> = Object.fromEntries(
    Object.entries(descriptions),
  )

  Object.setPrototypeOf(own, null)

  return Object.freeze(own)
}

/**
 * Check the pre-registered clients with the same rules as registration.
 *
 * @param clients - Configured clients.
 * @param scopes - The supported scopes after defaults were applied; a client's scopes must be a subset.
 * @param limits - Checked limits.
 * @param now - Clock.
 * @returns The clients by id.
 * @throws {McpAuthConfigError} When a client is invalid or listed twice.
 * @internal
 */
export function resolveStaticClients(
  clients: readonly StaticClient[] = [],
  scopes: readonly string[],
  limits: Required<Limits>,
  now: () => number,
): ReadonlyMap<string, ClientRecord> {
  const byId = new Map<string, ClientRecord>()

  for (const client of clients) {
    const id = client.clientId
    const label = `clients[${JSON.stringify(id)}]`

    if (id.trim() === "" || id.length > 255 || hasHiddenCharacters(id)) {
      throw new McpAuthConfigError(
        `${label}: clientId must be 1 to 255 visible characters`,
      )
    }

    if (isMetadataDocumentClientId(id) || /^https:/i.test(id)) {
      throw new McpAuthConfigError(
        `${label}: clientId must not be an https URL`,
      )
    }

    if (byId.has(id)) throw new McpAuthConfigError(`${label}: listed twice`)

    if (
      client.redirectUris.length === 0 ||
      client.redirectUris.length > limits.redirectUris
    ) {
      throw new McpAuthConfigError(
        `${label}: list 1 to ${limits.redirectUris} redirectUris`,
      )
    }

    for (const uri of client.redirectUris) {
      const problem = redirectUriProblem(uri, limits)

      if (problem !== undefined) {
        throw new McpAuthConfigError(
          `${label}: redirect URI refused (${problem})`,
        )
      }
    }

    const clientName =
      client.clientName === undefined
        ? undefined
        : cleanClientName(client.clientName, limits.clientNameLength)

    if (client.clientName !== undefined && clientName === undefined) {
      throw new McpAuthConfigError(
        `${label}: clientName is not a valid display name`,
      )
    }

    const grantTypes = parseGrantTypes(
      client.grantTypes ?? ["authorization_code", "refresh_token"],
      true,
    )

    if (grantTypes === undefined) {
      throw new McpAuthConfigError(
        `${label}: grantTypes must include authorization_code`,
      )
    }

    if (client.scopes?.some((scope) => !scopes.includes(scope)) === true) {
      throw new McpAuthConfigError(
        `${label}: scopes must be a subset of scopes`,
      )
    }

    if (client.scopes?.length === 0) {
      throw new McpAuthConfigError(`${label}: scopes must not be empty`)
    }

    // Frozen: the record is shared with every request and every hook.
    byId.set(
      id,
      freezeDeep({
        clientId: id,
        redirectUris: [...new Set(client.redirectUris)],
        kind: "static",
        createdAt: now(),
        grantTypes,
        ...(client.scopes !== undefined ? { scopes: [...client.scopes] } : {}),
        ...(clientName !== undefined ? { clientName } : {}),
      }),
    )
  }

  return byId
}
