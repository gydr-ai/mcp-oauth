import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  ClientRecord,
  ConsentRequest,
  ConsumedAuthorizationCode,
  StoredAuthorizationCode,
  GrantRecord,
  GrantUpstreamUpdate,
  PendingAuthorization,
  RefreshTokenRecord,
  UsedRefreshToken,
} from "./records.js"

/**
 * Persistence for the authorization server.
 *
 * ## Atomicity contract (MUST)
 *
 * Four operations decide who wins a race and MUST be atomic across every
 * process sharing the store (a conditional write, a transaction, a
 * compare-and-set, or a delete that returns the row; never a read followed by
 * a separate write):
 *
 * - `consumePendingAuthorization` and `consumeConsentRequest` hand the record
 *   to exactly one caller and delete it; a concurrent caller gets
 *   `undefined`. Otherwise one sign-in could complete twice and create two
 *   grants.
 * - `consumeAuthorizationCode`: exactly one caller sees `firstUse: true`.
 *   Otherwise an intercepted code could be redeemed in parallel with the real
 *   client (OAuth 2.1 § 4.1.3); the repeat is how the server notices and ends
 *   the grant.
 * - `useRefreshToken`: exactly one caller sees no `previousUsedAt`.
 *   Otherwise a copied refresh token could be rotated in parallel with the
 *   real client and replay detection (RFC 9700 § 4.14) would never trigger.
 *
 * Every read treats a record whose `expiresAt` has passed as absent (the
 * server checks again), with one exception: `consumeConsentRequest` SHOULD
 * still return (and delete) an expired consent request it holds, so the
 * upstream refresh token inside it can be revoked. Expired records may be
 * removed at any time, for example by a database TTL.
 *
 * ## Client lifetime (SHOULD)
 *
 * Dynamic clients cost nothing to create, so bound them without ever harming
 * a real one: never delete a client that has a live grant; delete a dynamic
 * client with no live grant that has not been looked up with `getClient` for
 * an idle period, and when a size cap is reached evict the least recently
 * used grant-less dynamic client first; never evict `static` clients.
 *
 * Only hashes of tokens and codes reach the store. Upstream tokens arrive
 * already encrypted by the `SecretSealer`.
 *
 * @example
 * ```ts
 * import type {
 *   AccessTokenRecord,
 *   AuthorizationCodeRecord,
 *   ClientKind,
 *   ClientRecord,
 *   ConsentRequest,
 *   ConsumedAuthorizationCode,
 *   GrantRecord,
 *   GrantUpstreamUpdate,
 *   OAuthStore,
 *   PendingAuthorization,
 *   RefreshTokenRecord,
 *   StoredAuthorizationCode,
 *   SupportedGrantType,
 *   UsedRefreshToken,
 * } from "@gydr-ai/mcp-oauth"
 *
 * // Sketch of a database-backed store. `db` stands for your own data layer;
 * // each "atomic" call must be a single conditional write in your database.
 * declare const db: {
 *   get<T>(table: string, key: string): Promise<T | undefined>
 *   put(table: string, key: string, value: object): Promise<void>
 *   remove(table: string, key: string): Promise<void>
 *   takeAtomically<T>(table: string, key: string): Promise<T | undefined>
 *   markCodeUsedAtomically(hash: string): Promise<ConsumedAuthorizationCode | undefined>
 *   readCode(hash: string): Promise<StoredAuthorizationCode | undefined>
 *   markRefreshUsedAtomically(hash: string, now: number): Promise<UsedRefreshToken | undefined>
 *   updateIfExists(table: string, key: string, patch: GrantUpstreamUpdate): Promise<boolean>
 * }
 *
 * export const evictable: readonly ClientKind[] = ["dynamic"]
 * export const minimalGrantTypes: readonly SupportedGrantType[] = ["authorization_code"]
 *
 * export const store: OAuthStore = {
 *   getClient: (id) => db.get<ClientRecord>("clients", id),
 *   putClient: (client) => db.put("clients", client.clientId, client),
 *   getCachedClientMetadata: (url) => db.get<ClientRecord>("metadata", url),
 *   putCachedClientMetadata: (url, client) => db.put("metadata", url, client),
 *   putPendingAuthorization: (p: PendingAuthorization) => db.put("pending", p.id, p),
 *   getPendingAuthorization: (id) => db.get<PendingAuthorization>("pending", id),
 *   consumePendingAuthorization: (id) => db.takeAtomically<PendingAuthorization>("pending", id),
 *   putConsentRequest: (c: ConsentRequest) => db.put("consent", c.id, c),
 *   getConsentRequest: (id) => db.get<ConsentRequest>("consent", id),
 *   consumeConsentRequest: (id) => db.takeAtomically<ConsentRequest>("consent", id),
 *   putAuthorizationCode: (c: AuthorizationCodeRecord) => db.put("codes", c.codeHash, c),
 *   getAuthorizationCode: (hash) => db.readCode(hash),
 *   consumeAuthorizationCode: (hash) => db.markCodeUsedAtomically(hash),
 *   putGrant: (g: GrantRecord) => db.put("grants", g.grantId, g),
 *   getGrant: (id) => db.get<GrantRecord>("grants", id),
 *   updateGrant: (id, patch) => db.updateIfExists("grants", id, patch),
 *   deleteGrant: (id) => db.remove("grants", id),
 *   putAccessToken: (t: AccessTokenRecord) => db.put("access", t.tokenHash, t),
 *   getAccessToken: (hash) => db.get<AccessTokenRecord>("access", hash),
 *   deleteAccessToken: (hash) => db.remove("access", hash),
 *   putRefreshToken: (t: RefreshTokenRecord) => db.put("refresh", t.tokenHash, t),
 *   getRefreshToken: (hash) => db.get<RefreshTokenRecord>("refresh", hash),
 *   useRefreshToken: (hash, now) => db.markRefreshUsedAtomically(hash, now),
 * }
 * ```
 */
export interface OAuthStore {
  /** A dynamic or static client by `client_id`. */
  getClient(clientId: string): Promise<ClientRecord | undefined>
  /** Save a dynamic or static client. */
  putClient(client: ClientRecord): Promise<void>

  /** A cached, already validated Client ID Metadata Document. */
  getCachedClientMetadata(url: string): Promise<ClientRecord | undefined>
  /** Cache a validated Client ID Metadata Document until `expiresAt`. */
  putCachedClientMetadata(
    url: string,
    client: ClientRecord,
    expiresAt: number,
  ): Promise<void>

  /** Save a pending authorization. */
  putPendingAuthorization(pending: PendingAuthorization): Promise<void>
  /** Read a pending authorization without consuming it. */
  getPendingAuthorization(id: string): Promise<PendingAuthorization | undefined>
  /** Atomically read and delete a pending authorization. */
  consumePendingAuthorization(
    id: string,
  ): Promise<PendingAuthorization | undefined>

  /** Save a consent request. */
  putConsentRequest(request: ConsentRequest): Promise<void>
  /**
   * Read a consent request without consuming it, including an expired one
   * the store still holds (the server checks the expiry itself). Used to
   * check the form token before anything is used up, and to show the page
   * again when extra fields need correcting.
   */
  getConsentRequest(id: string): Promise<ConsentRequest | undefined>
  /**
   * Atomically read and delete a consent request. Should also return an
   * expired one it still holds.
   */
  consumeConsentRequest(id: string): Promise<ConsentRequest | undefined>

  /** Save an authorization code. */
  putAuthorizationCode(code: AuthorizationCodeRecord): Promise<void>
  /**
   * Read a code without using it up, consumed or not, until it expires. The
   * token endpoint checks the client, redirect URI, resource and PKCE
   * verifier against it first, so a wrong guess never spends the code.
   */
  getAuthorizationCode(
    codeHash: string,
  ): Promise<StoredAuthorizationCode | undefined>
  /**
   * Atomically mark a code consumed and return it. The record stays readable
   * (with `firstUse: false`) until it expires so a repeat can be detected.
   */
  consumeAuthorizationCode(
    codeHash: string,
  ): Promise<ConsumedAuthorizationCode | undefined>

  /** Save a grant. */
  putGrant(grant: GrantRecord): Promise<void>
  /** Read a grant. */
  getGrant(grantId: string): Promise<GrantRecord | undefined>
  /**
   * Update the upstream-token fields of an existing grant. Resolves `false`,
   * writing nothing, when the grant no longer exists.
   */
  updateGrant(grantId: string, update: GrantUpstreamUpdate): Promise<boolean>
  /**
   * Remove a grant. Afterwards `getGrant` returns `undefined`. Deleting the
   * grant's tokens too is recommended; the server checks the grant on every
   * use anyway.
   *
   * Recommended: resolve with the record as it was deleted (a delete that
   * returns the row). The upstream refresh token revoked at the identity
   * provider is then exactly the last one stored, even when a renewal
   * replaced it a moment earlier. Resolving nothing is allowed; the server
   * then uses the record it read just before deleting. The value is typed
   * `unknown` so stores that resolve `void` still fit; the server uses it
   * only when it is an object with this `grantId`.
   */
  deleteGrant(grantId: string): Promise<unknown>

  /** Save an access token record. */
  putAccessToken(token: AccessTokenRecord): Promise<void>
  /** Read an access token record. */
  getAccessToken(tokenHash: string): Promise<AccessTokenRecord | undefined>
  /** Delete an access token record. */
  deleteAccessToken(tokenHash: string): Promise<void>

  /** Save a refresh token record. */
  putRefreshToken(token: RefreshTokenRecord): Promise<void>
  /** Read a refresh token record without marking it used. */
  getRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | undefined>
  /** Atomically set `usedAt` if it is not set yet. */
  useRefreshToken(
    tokenHash: string,
    now: number,
  ): Promise<UsedRefreshToken | undefined>

  /**
   * Optional: remember the answer to a consent submission for a few
   * seconds, keyed by a hash of the browser cookie and the form token, so a
   * repeated submission gets the same redirect. `sealedLocation` is
   * encrypted. Without this method (and `getConsentOutcome`), a repeat is
   * answered with an error page.
   */
  putConsentOutcome?(
    key: string,
    sealedLocation: string,
    expiresAt: number,
  ): Promise<void>
  /** Optional: read a remembered consent answer (see `putConsentOutcome`). */
  getConsentOutcome?(key: string): Promise<string | undefined>
  /**
   * Optional: every live grant of one person, for
   * `McpAuth.revokeGrantsForSubject`.
   */
  listGrantsBySubject?(subject: string): Promise<readonly GrantRecord[]>
}
