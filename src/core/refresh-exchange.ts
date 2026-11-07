import { EndpointRefusal } from "../errors/endpoint-refusal.js"
import { isRecord } from "../helpers/guards.js"
import { single, type Params } from "../helpers/params.js"
import { isOpaqueToken, sha256Hex } from "../helpers/tokens.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { RefreshTokenRecord } from "../interfaces/records.js"
import type { RevokeGrant } from "../interfaces/routes.js"
import type { TokenResponse } from "../interfaces/token-response.js"
import { requireOwnResource } from "./client-form.js"
import { issueTokenPair, liveGrant } from "./grants.js"
import { requireTokenIssue } from "./token-policy.js"
import { hasExpired } from "../helpers/time.js"
import { slidGrantExpiry } from "./grant-expiry.js"

/**
 * Exchange a refresh token for a new access token and a rotated refresh
 * token (OAuth 2.1 § 4.3).
 *
 * @param context - Context supplying the store, clock, retry window, hooks and token lifetimes.
 * @param form - Parsed token-endpoint form, already checked for repeated parameters and client credentials.
 * @param clientId - The `client_id` sent with the request; the refresh token must have been issued to it.
 * @param revoke - Ends a grant; used when a spent refresh token is presented again outside the retry window, or after the pair it was exchanged for has been used.
 * @returns The RFC 6749 § 5.1 token response with a rotated refresh token; for a retry inside the window, the pair the first exchange issued (or, with a store that keeps no replacements, an access token only).
 * @throws {EndpointRefusal} When the token is missing, unknown, expired, another client's, replayed, asks for wider scopes, or its grant is gone.
 * @internal
 */
export async function exchangeRefreshToken(
  context: HandlerContext,
  form: Params,
  clientId: string,
  revoke: RevokeGrant,
): Promise<TokenResponse> {
  const { options } = context
  const presented = single(form, "refresh_token")

  if (presented === undefined) {
    throw new EndpointRefusal(
      "invalid_request",
      "Missing parameter: refresh_token",
    )
  }

  requireOwnResource(context, form)

  const unusable = () =>
    new EndpointRefusal("invalid_grant", "This refresh token cannot be used")

  if (!isOpaqueToken(presented)) throw unusable()

  const hash = sha256Hex(presented)
  const now = options.now()
  // Look before marking: a different client presenting the token must not
  // be able to use it up.
  const known = await options.store.getRefreshToken(hash)

  if (
    known === undefined ||
    known.clientId !== clientId ||
    hasExpired(known.expiresAt, now)
  ) {
    throw unusable()
  }

  let scopes = known.scopes
  const narrowed = single(form, "scope")

  if (narrowed !== undefined) {
    const asked = [...new Set(narrowed.split(" ").filter((s) => s.length > 0))]

    if (asked.length === 0 || asked.some((s) => !known.scopes.includes(s))) {
      throw new EndpointRefusal(
        "invalid_scope",
        "A refreshed token can only carry scopes already granted",
      )
    }

    scopes = asked
  }

  // Checked before the token is marked used, so a refusal or a failing
  // check leaves it usable.
  const current = await liveGrant(context, known.grantId, clientId)

  if (current === undefined || current.allowRefresh === false) {
    throw new EndpointRefusal("invalid_grant", "Access has been withdrawn")
  }

  await requireTokenIssue(context, current, "refresh_token")

  const marked = await options.store.useRefreshToken(hash, now)

  if (marked === undefined) throw unusable()

  const earlier = marked.previousUsedAt

  if (earlier !== undefined) {
    const withinRetryWindow =
      options.refreshReuseGraceMs > 0 &&
      now - earlier <= options.refreshReuseGraceMs

    if (!withinRetryWindow) {
      // Presented again after it was spent, outside the retry window: assume
      // it was copied and withdraw everything issued under it (OAuth 2.1 §
      // 4.3.1, RFC 9700 § 4.14).
      await endReplayedGrant(context, marked.record.grantId, clientId, revoke)

      throw unusable()
    }

    return answerRetry(context, marked.record, scopes, clientId, revoke)
  }

  const grant = await liveGrant(context, marked.record.grantId, clientId)

  if (grant === undefined || grant.allowRefresh === false) {
    throw new EndpointRefusal("invalid_grant", "Access has been withdrawn")
  }

  // Under `lifetimes.grantIdle` a renewal extends the grant, never past its
  // absolute limit. The tokens below follow the new expiry only when the
  // store accepted the update; every later check reads the stored grant, so
  // a store that ignored `expiresAt` still ends the grant on time.
  const slid = slidGrantExpiry(options, grant, now)
  const renewed =
    slid !== undefined &&
    (await options.store.updateGrant(grant.grantId, { expiresAt: slid }))
      ? { ...grant, expiresAt: slid }
      : grant

  // A narrowed request narrows only this access token; the new refresh
  // token keeps the scopes it replaces (OAuth 2.1 § 4.3.1, RFC 6749 § 6).
  const tokens = await issueTokenPair(context, renewed, scopes, known.scopes)

  await keepReplacement(context, marked.record, tokens, now)

  await context.emit({
    type: "token_issued",
    grantId: grant.grantId,
    clientId,
    subject: grant.subject,
    grantType: "refresh_token",
  })

  return tokens
}

/**
 * The pair a refresh exchange issued, kept encrypted on the spent refresh
 * token so a retry inside the window receives exactly the same pair.
 */
interface IssuedReplacement {
  readonly accessToken: string
  readonly refreshToken: string
  readonly scope: string
  readonly accessExpiresAt: number
}

/**
 * Additional authenticated data binding a sealed replacement to the spent
 * refresh token it was issued for, so it cannot be moved to another record.
 *
 * @param spent - The spent refresh token record.
 * @returns The `aad` string for the sealer.
 */
function replacementAad(spent: RefreshTokenRecord): string {
  return `${spent.grantId}#refresh-replacement#${spent.tokenHash}`
}

/**
 * Read a decrypted replacement, refusing anything that is not one.
 *
 * @param plaintext - The opened value.
 * @returns The replacement, or `undefined` when the value is malformed.
 */
function parseReplacement(plaintext: string): IssuedReplacement | undefined {
  let value: unknown

  try {
    value = JSON.parse(plaintext)
  } catch {
    return undefined
  }

  if (
    !isRecord(value) ||
    typeof value.accessToken !== "string" ||
    typeof value.refreshToken !== "string" ||
    typeof value.scope !== "string" ||
    typeof value.accessExpiresAt !== "number"
  ) {
    return undefined
  }

  return {
    accessToken: value.accessToken,
    refreshToken: value.refreshToken,
    scope: value.scope,
    accessExpiresAt: value.accessExpiresAt,
  }
}

/**
 * Keep the pair just issued for a refresh token, encrypted on the spent
 * token's record, when the store implements `putRefreshTokenReplacement`.
 *
 * @param context - Context supplying the store and sealer.
 * @param spent - The refresh token this exchange used up.
 * @param tokens - The response being returned.
 * @param now - The time the exchange started.
 */
async function keepReplacement(
  context: HandlerContext,
  spent: RefreshTokenRecord,
  tokens: TokenResponse,
  now: number,
): Promise<void> {
  const { store, sealer } = context.options

  if (
    store.putRefreshTokenReplacement === undefined ||
    tokens.refresh_token === undefined
  ) {
    return
  }

  const replacement: IssuedReplacement = {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    scope: tokens.scope,
    accessExpiresAt: now + tokens.expires_in * 1000,
  }

  await store.putRefreshTokenReplacement(
    spent.tokenHash,
    await sealer.seal(JSON.stringify(replacement), replacementAad(spent)),
  )
}

/**
 * Report a replayed refresh token and end its grant.
 *
 * @param context - Context supplying the event hook.
 * @param grantId - The grant the replayed token belongs to.
 * @param clientId - The client presenting it.
 * @param revoke - Ends the grant.
 */
async function endReplayedGrant(
  context: HandlerContext,
  grantId: string,
  clientId: string,
  revoke: RevokeGrant,
): Promise<void> {
  await context.emit({ type: "refresh_token_replayed", grantId, clientId })
  await revoke(grantId, "refresh_token_replay")
}

/**
 * Answer a spent refresh token presented again inside the retry window
 * without ever starting a second token chain.
 *
 * With a store that keeps replacements, the retry receives the very pair the
 * first exchange issued, so whoever else holds the token shares that one
 * chain: once either holder rotates it, the other's next use is a replay and
 * the grant ends. A retry after the replacement was itself used is already
 * that replay. Without `putRefreshTokenReplacement`, the retry receives an
 * access token only.
 *
 * @param context - Context supplying the store, sealer and token lifetimes.
 * @param spent - The spent refresh token record.
 * @param scopes - Scopes for a new access token (store without replacements only).
 * @param clientId - The client presenting the token.
 * @param revoke - Ends the grant when the retry turns out to be a replay.
 * @returns The original pair, or a new access token without a refresh token.
 * @throws {EndpointRefusal} `temporarily_unavailable` while the first exchange is still storing its pair; `invalid_grant` when the pair cannot be replayed.
 */
async function answerRetry(
  context: HandlerContext,
  spent: RefreshTokenRecord,
  scopes: readonly string[],
  clientId: string,
  revoke: RevokeGrant,
): Promise<TokenResponse> {
  const { options } = context
  const unusable = () =>
    new EndpointRefusal("invalid_grant", "This refresh token cannot be used")

  if (options.store.putRefreshTokenReplacement === undefined) {
    const grant = await liveGrant(context, spent.grantId, clientId)

    if (grant === undefined) {
      throw new EndpointRefusal("invalid_grant", "Access has been withdrawn")
    }

    // No refresh token: a second refresh token here would be an independent
    // chain that replay detection could never connect to the first.
    const tokens = await issueTokenPair(
      context,
      { ...grant, allowRefresh: false },
      scopes,
    )

    await context.emit({
      type: "token_issued",
      grantId: grant.grantId,
      clientId,
      subject: grant.subject,
      grantType: "refresh_token",
    })

    return tokens
  }

  if (spent.sealedReplacement === undefined) {
    // The first exchange has marked the token but not stored its pair yet.
    throw new EndpointRefusal(
      "temporarily_unavailable",
      "This refresh token is being exchanged; retry shortly",
      503,
    )
  }

  const replacement = parseReplacement(
    await options.sealer.open(spent.sealedReplacement, replacementAad(spent)),
  )

  if (replacement === undefined) throw unusable()

  const next = await options.store.getRefreshToken(
    sha256Hex(replacement.refreshToken),
  )

  if (next?.usedAt !== undefined) {
    // The pair already moved on: someone else holds this token too.
    await endReplayedGrant(context, spent.grantId, clientId, revoke)

    throw unusable()
  }

  if (next === undefined) throw unusable()

  return {
    access_token: replacement.accessToken,
    token_type: "Bearer",
    expires_in: Math.max(
      0,
      Math.floor((replacement.accessExpiresAt - options.now()) / 1000),
    ),
    scope: replacement.scope,
    refresh_token: replacement.refreshToken,
  }
}
