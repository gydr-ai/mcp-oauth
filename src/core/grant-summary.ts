import type { GrantSummary } from "../interfaces/consent.js"
import type { GrantRecord } from "../interfaces/records.js"
import { frozenCopy } from "../helpers/freeze.js"

/**
 * A deeply frozen copy of a grant without its encrypted upstream tokens,
 * for hooks and events.
 *
 * @param grant - The stored grant.
 * @returns The summary.
 * @internal
 */
export function grantSummary(grant: GrantRecord): GrantSummary {
  // An allow-list, so a field added to GrantRecord later is never exposed
  // by accident.
  return frozenCopy({
    grantId: grant.grantId,
    clientId: grant.clientId,
    subject: grant.subject,
    scopes: grant.scopes,
    resource: grant.resource,
    createdAt: grant.createdAt,
    expiresAt: grant.expiresAt,
    ...(grant.clientName !== undefined ? { clientName: grant.clientName } : {}),
    ...(grant.displayName !== undefined
      ? { displayName: grant.displayName }
      : {}),
    ...(grant.allowRefresh !== undefined
      ? { allowRefresh: grant.allowRefresh }
      : {}),
    ...(grant.data !== undefined ? { data: grant.data } : {}),
    ...(grant.redirectUri !== undefined
      ? { redirectUri: grant.redirectUri }
      : {}),
  })
}
