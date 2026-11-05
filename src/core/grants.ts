import { randomToken, sha256Hex } from "../helpers/tokens.js"
import { isRecord } from "../helpers/guards.js"
import { grantSummary } from "./grant-summary.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { GrantRevokeReason } from "../interfaces/events.js"
import type { GrantRecord } from "../interfaces/records.js"
import type { TokenResponse } from "../interfaces/token-response.js"
import { hasExpired } from "../helpers/time.js"

/**
 * Mint and store an access token (and, unless the client did not register
 * the refresh_token grant, a refresh token) for a grant. The refresh token's
 * window slides but never passes the grant's absolute expiry.
 *
 * @param context - Context supplying the store, clock and token lifetimes.
 * @param grant - The live grant the tokens are issued under; its `expiresAt` caps both token lifetimes and `allowRefresh` decides whether a refresh token is issued.
 * @param scopes - Scopes the access token carries; already checked to be within the grant's scopes.
 * @param refreshScopes - Scopes the refresh token carries. Default: `scopes`.
 * @returns The RFC 6749 § 5.1 response body; `refresh_token` is absent when the grant does not allow refresh.
 * @internal
 */
export async function issueTokenPair(
  context: HandlerContext,
  grant: GrantRecord,
  scopes: readonly string[],
  refreshScopes: readonly string[] = scopes,
): Promise<TokenResponse> {
  const { options } = context
  const now = options.now()
  const accessToken = randomToken()
  const accessExpiresAt = Math.min(
    now + options.accessTokenTtlMs,
    grant.expiresAt,
  )

  await options.store.putAccessToken({
    tokenHash: sha256Hex(accessToken),
    grantId: grant.grantId,
    clientId: grant.clientId,
    scopes,
    resource: grant.resource,
    expiresAt: accessExpiresAt,
  })

  const response = {
    access_token: accessToken,
    token_type: "Bearer" as const,
    expires_in: Math.max(0, Math.floor((accessExpiresAt - now) / 1000)),
    scope: scopes.join(" "),
  }

  if (grant.allowRefresh === false) return response

  const refreshToken = randomToken()

  await options.store.putRefreshToken({
    tokenHash: sha256Hex(refreshToken),
    grantId: grant.grantId,
    clientId: grant.clientId,
    scopes: refreshScopes,
    resource: grant.resource,
    expiresAt: Math.min(now + options.refreshTokenTtlMs, grant.expiresAt),
  })

  return { ...response, refresh_token: refreshToken }
}

/**
 * The grant when it exists, is unexpired and belongs to `clientId`.
 *
 * @param context - Context supplying the store and clock.
 * @param grantId - Grant id taken from a stored token or code record.
 * @param clientId - Client the caller claims to be; the grant must belong to it.
 * @returns The grant when it exists, has not reached its absolute expiry and belongs to `clientId`; otherwise `undefined`.
 * @internal
 */
export async function liveGrant(
  context: HandlerContext,
  grantId: string,
  clientId: string,
): Promise<GrantRecord | undefined> {
  const grant = await context.options.store.getGrant(grantId)

  if (
    grant === undefined ||
    grant.clientId !== clientId ||
    hasExpired(grant.expiresAt, context.options.now())
  ) {
    return undefined
  }

  return grant
}

/**
 * Revoke an upstream refresh token at the IdP. Best effort, never throws.
 *
 * @param context - Context supplying the identity provider whose optional `revoke` is called.
 * @param refreshToken - Plaintext upstream refresh token, as returned by the identity provider.
 * @internal
 */
export async function revokeUpstreamToken(
  context: HandlerContext,
  refreshToken: string,
): Promise<void> {
  const provider = context.options.identityProvider

  if (provider.revoke === undefined) return

  try {
    await provider.revoke(refreshToken)
  } catch {
    // Best effort: nothing on our side holds the token any more.
  }
}

/**
 * Open a sealed upstream refresh token and revoke it. Best effort.
 *
 * @param context - Context supplying the sealer and identity provider.
 * @param sealed - Upstream refresh token encrypted with additional data `grantId`; nothing happens when `undefined`.
 * @param grantId - Grant id the value was encrypted for; used as the additional authenticated data.
 * @internal
 */
export async function revokeSealedUpstreamToken(
  context: HandlerContext,
  sealed: string | undefined,
  grantId: string,
): Promise<void> {
  if (
    sealed === undefined ||
    context.options.identityProvider.revoke === undefined
  ) {
    return
  }

  let plaintext: string

  try {
    plaintext = await context.options.sealer.open(sealed, grantId)
  } catch {
    return
  }

  await revokeUpstreamToken(context, plaintext)
}

/**
 * End a grant. The `grant_revoked` event (with a copy of the grant, minus
 * its encrypted upstream tokens) is emitted first. Removing the record
 * invalidates all tokens tied to it.
 *
 * The upstream refresh token revoked at the identity provider is the last
 * one stored: the record the store returns from `deleteGrant`, or else the
 * one read just before deleting. `onRevoking` runs before both, so an
 * upstream renewal under way in this process sees the grant ending and
 * revokes the token it was about to store itself.
 *
 * @param context - Context supplying the store, sealer, identity provider and event hook.
 * @param grantId - Id of the grant to end; unknown ids are a silent no-op.
 * @param reason - Why the grant ends; reported in the `grant_revoked` event.
 * @param onRevoking - Called synchronously before the delete, so in-memory state for the grant can be dropped.
 * @internal
 */
export async function revokeGrantById(
  context: HandlerContext,
  grantId: string,
  reason: GrantRevokeReason,
  onRevoking: (grantId: string) => void,
): Promise<void> {
  const { options } = context
  const grant = await options.store.getGrant(grantId)

  // Reported before the delete, so a listener still finds the grant (and
  // whatever it keeps about it) in the store.
  if (grant !== undefined) {
    await context.emit({
      type: "grant_revoked",
      grantId,
      reason,
      grant: grantSummary(grant),
    })
  }

  onRevoking(grantId)

  // Read again: a renewal may have stored a new upstream token meanwhile.
  const latest = await options.store.getGrant(grantId)
  const deleted: unknown = await options.store.deleteGrant(grantId)
  const sealed =
    isRecord(deleted) && deleted.grantId === grantId
      ? deleted.sealedUpstreamRefreshToken
      : (latest ?? grant)?.sealedUpstreamRefreshToken

  if (sealed !== undefined && typeof sealed !== "string") return

  await revokeSealedUpstreamToken(context, sealed, grantId)
}
