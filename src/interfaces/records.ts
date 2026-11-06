/*
 * The records an `OAuthStore` keeps. All times are milliseconds since the
 * Unix epoch, as returned by `Date.now()`.
 */

/**
 * How a client made itself known to this server.
 *
 * @example
 * ```ts
 * import type { ClientKind, ClientRecord } from "@gydr-ai/mcp-oauth"
 *
 * export function isOperatorClient(client: ClientRecord): boolean {
 *   const kind: ClientKind = client.kind
 *
 *   return kind === "static"
 * }
 * ```
 */
export type ClientKind = "dynamic" | "metadata_document" | "static"

/**
 * A grant type this server can issue tokens for.
 *
 * @example
 * ```ts
 * import type { ClientRecord, SupportedGrantType } from "@gydr-ai/mcp-oauth"
 *
 * export function mayRefresh(client: ClientRecord): boolean {
 *   const wanted: SupportedGrantType = "refresh_token"
 *
 *   return client.grantTypes?.includes(wanted) ?? true
 * }
 * ```
 */
export type SupportedGrantType = "authorization_code" | "refresh_token"

/**
 * A known OAuth client. Every client is public: it holds no secret and proves
 * possession of each authorization with PKCE instead.
 *
 * @example
 * ```ts
 * import type { ClientRecord, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function findClient(store: OAuthStore, id: string): Promise<ClientRecord | undefined> {
 *   return store.getClient(id)
 * }
 * ```
 */
export interface ClientRecord {
  /** The `client_id`. For a Client ID Metadata Document, the document URL. */
  readonly clientId: string
  /** Display name, already checked for hidden characters. */
  readonly clientName?: string
  /** Registered redirect URIs, already validated. */
  readonly redirectUris: readonly string[]
  /**
   * `dynamic` (registered through RFC 7591, name self-declared),
   * `metadata_document` (downloaded from the `client_id` URL, host proven by
   * HTTPS, name still self-declared) or `static` (added by the operator).
   */
  readonly kind: ClientKind
  /** When the client registered, or when its document was downloaded. */
  readonly createdAt: number
  /**
   * Grant types the client registered. Without `refresh_token` the client
   * receives no refresh tokens. Default: both grant types (records written by
   * the operator).
   */
  readonly grantTypes?: readonly SupportedGrantType[]
  /**
   * Scopes the client registered; requests may only ask within them.
   * Default: any supported scope.
   */
  readonly scopes?: readonly string[]
}

/**
 * An authorization request waiting for the person to sign in.
 *
 * @example
 * ```ts
 * import type { PendingAuthorization, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function peek(store: OAuthStore, id: string): Promise<PendingAuthorization | undefined> {
 *   return store.getPendingAuthorization(id)
 * }
 * ```
 */
export interface PendingAuthorization {
  /** Random flow id; also the `state` sent to the identity provider. */
  readonly id: string
  /** The requesting client. */
  readonly clientId: string
  /** The client's display name at the time of the request. */
  readonly clientName?: string
  /** How the client made itself known. */
  readonly clientKind: ClientKind
  /** Redirect URI of this request, already matched against registration. */
  readonly redirectUri: string
  /** Opaque `state` from the client, returned unchanged. */
  readonly state?: string
  /** S256 code challenge supplied by the client. */
  readonly codeChallenge: string
  /** The resource (RFC 8707) the tokens will be for. */
  readonly resource: string
  /** Scopes being requested. */
  readonly scopes: readonly string[]
  /** PKCE verifier this server uses toward the identity provider. */
  readonly upstreamCodeVerifier: string
  /** OpenID Connect nonce this server uses toward the identity provider. */
  readonly upstreamNonce: string
  /** SHA-256 (hex) of the browser-binding cookie value. */
  readonly bindingHash: string
  /** `false` when the client did not register the refresh_token grant. */
  readonly allowRefresh?: boolean
  /** When the flow stops being usable. */
  readonly expiresAt: number
}

/**
 * The person has signed in and the consent screen is showing. Holds the
 * upstream tokens, already encrypted for the grant id approval will create.
 *
 * @example
 * ```ts
 * import type { ConsentRequest, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function take(store: OAuthStore, id: string): Promise<ConsentRequest | undefined> {
 *   return store.consumeConsentRequest(id)
 * }
 * ```
 */
export interface ConsentRequest {
  /** Random id carried by the consent form. */
  readonly id: string
  /** The grant id the upstream tokens are encrypted for. */
  readonly grantId: string
  /** The requesting client. */
  readonly clientId: string
  /** The client's display name. */
  readonly clientName?: string
  /** How the client made itself known. */
  readonly clientKind: ClientKind
  /** Where the result will be delivered. */
  readonly redirectUri: string
  /** Opaque `state` from the client. */
  readonly state?: string
  /** S256 code challenge supplied by the client. */
  readonly codeChallenge: string
  /** The resource the tokens will be for. */
  readonly resource: string
  /** Scopes being requested. */
  readonly scopes: readonly string[]
  /** The person's stable id at the identity provider (`sub`). */
  readonly subject: string
  /** How the identity provider names the person. */
  readonly displayName?: string
  /** Upstream refresh token, encrypted with additional data `grantId`. */
  readonly sealedUpstreamRefreshToken?: string
  /** Upstream access token, encrypted with additional data `grantId#access`. */
  readonly sealedUpstreamAccessToken?: string
  /** When the upstream access token expires. */
  readonly upstreamAccessTokenExpiresAt?: number
  /** `false` when the client did not register the refresh_token grant. */
  readonly allowRefresh?: boolean
  /** What `getConsentDetails` returned for this screen (JSON), if anything. */
  readonly details?: unknown
  /** SHA-256 (hex) of the consent form's one-time token. */
  readonly csrfHash: string
  /** SHA-256 (hex) of the browser-binding cookie value. */
  readonly bindingHash: string
  /** When the consent screen stops being usable. */
  readonly expiresAt: number
}

/**
 * A single-use authorization code, stored by hash.
 *
 * @example
 * ```ts
 * import type { AuthorizationCodeRecord, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function save(store: OAuthStore, code: AuthorizationCodeRecord): Promise<void> {
 *   return store.putAuthorizationCode(code)
 * }
 * ```
 */
export interface AuthorizationCodeRecord {
  /** SHA-256 (hex) of the code. The code itself is never stored. */
  readonly codeHash: string
  /** The grant the code was issued under. */
  readonly grantId: string
  /** The client the code was issued to. */
  readonly clientId: string
  /** The redirect URI the code was delivered to. */
  readonly redirectUri: string
  /** The client's S256 code challenge. */
  readonly codeChallenge: string
  /** The resource the tokens will be for. */
  readonly resource: string
  /** Scopes granted. */
  readonly scopes: readonly string[]
  /** When the code expires. */
  readonly expiresAt: number
}

/**
 * Result of `OAuthStore.consumeAuthorizationCode`.
 *
 * @example
 * ```ts
 * import type { ConsumedAuthorizationCode, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function redeem(store: OAuthStore, hash: string): Promise<ConsumedAuthorizationCode | undefined> {
 *   return store.consumeAuthorizationCode(hash)
 * }
 * ```
 */
export interface ConsumedAuthorizationCode {
  /** The code record. */
  readonly record: AuthorizationCodeRecord
  /**
   * `true` for exactly one caller, the first to consume the code; every later
   * caller sees `false`.
   */
  readonly firstUse: boolean
}

/**
 * Result of `OAuthStore.getAuthorizationCode`: a code record read without
 * using it up.
 *
 * @example
 * ```ts
 * import type { OAuthStore, StoredAuthorizationCode } from "@gydr-ai/mcp-oauth"
 *
 * export function peekCode(store: OAuthStore, hash: string): Promise<StoredAuthorizationCode | undefined> {
 *   return store.getAuthorizationCode(hash)
 * }
 * ```
 */
export interface StoredAuthorizationCode {
  /** The code record. */
  readonly record: AuthorizationCodeRecord
  /** Whether `consumeAuthorizationCode` has already been called for it. */
  readonly consumed: boolean
}

/**
 * One person's approval of one client: the long-lived authorization behind
 * every token. Deleting it invalidates every token tied to it.
 *
 * @example
 * ```ts
 * import type { GrantRecord, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function findGrant(store: OAuthStore, id: string): Promise<GrantRecord | undefined> {
 *   return store.getGrant(id)
 * }
 * ```
 */
export interface GrantRecord {
  /** Random grant id. */
  readonly grantId: string
  /** The approved client. */
  readonly clientId: string
  /** The client's display name at approval time. */
  readonly clientName?: string
  /** The person's stable id at the identity provider. */
  readonly subject: string
  /** How the identity provider names the person. */
  readonly displayName?: string
  /** Scopes granted. */
  readonly scopes: readonly string[]
  /** The resource the tokens are for. */
  readonly resource: string
  /** Upstream refresh token, encrypted with additional data `grantId`. */
  readonly sealedUpstreamRefreshToken?: string
  /** Upstream access token, encrypted with additional data `grantId#access`. */
  readonly sealedUpstreamAccessToken?: string
  /** When the upstream access token expires. */
  readonly upstreamAccessTokenExpiresAt?: number
  /**
   * `false` when the client did not register the refresh_token grant: no
   * refresh tokens are issued under this grant. Default: allowed.
   */
  readonly allowRefresh?: boolean
  /**
   * Data the integrator attached to the grant through `readConsentFields`
   * or `McpAuth.updateGrantData` (JSON, at most `limits.grantDataBytes`).
   */
  readonly data?: unknown
  /** The redirect URI the approved authorization was sent to. */
  readonly redirectUri?: string
  /** When the person approved. */
  readonly createdAt: number
  /**
   * End of the grant; no token outlives it. With `lifetimes.grantIdle` it
   * moves forward on each refresh, never past `createdAt + lifetimes.grant`.
   */
  readonly expiresAt: number
}

/**
 * The fields of a grant that may change after creation.
 *
 * @example
 * ```ts
 * import type { GrantUpstreamUpdate, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function saveRenewal(store: OAuthStore, id: string, update: GrantUpstreamUpdate): Promise<boolean> {
 *   return store.updateGrant(id, update)
 * }
 * ```
 */
export interface GrantUpstreamUpdate {
  /** New encrypted upstream refresh token. */
  readonly sealedUpstreamRefreshToken?: string
  /** New encrypted upstream access token. */
  readonly sealedUpstreamAccessToken?: string
  /** Expiry of the new upstream access token. */
  readonly upstreamAccessTokenExpiresAt?: number
  /** New integrator data for the grant (see `GrantRecord.data`). */
  readonly data?: unknown
  /** New end of the grant, after a refresh under `lifetimes.grantIdle`. */
  readonly expiresAt?: number
}

/**
 * An issued access token, stored by hash.
 *
 * @example
 * ```ts
 * import type { AccessTokenRecord, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function findAccess(store: OAuthStore, hash: string): Promise<AccessTokenRecord | undefined> {
 *   return store.getAccessToken(hash)
 * }
 * ```
 */
export interface AccessTokenRecord {
  /** SHA-256 (hex) of the token. */
  readonly tokenHash: string
  /** The grant the token belongs to. */
  readonly grantId: string
  /** The client the token was issued to. */
  readonly clientId: string
  /** Scopes the token carries. */
  readonly scopes: readonly string[]
  /** The audience (RFC 8707 resource) the token was issued for. */
  readonly resource: string
  /** When the token expires. */
  readonly expiresAt: number
}

/**
 * An issued refresh token, stored by hash.
 *
 * @example
 * ```ts
 * import type { RefreshTokenRecord, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function findRefresh(store: OAuthStore, hash: string): Promise<RefreshTokenRecord | undefined> {
 *   return store.getRefreshToken(hash)
 * }
 * ```
 */
export interface RefreshTokenRecord {
  /** SHA-256 (hex) of the token. */
  readonly tokenHash: string
  /** The grant the token belongs to. */
  readonly grantId: string
  /** The client the token was issued to. */
  readonly clientId: string
  /** Scopes the token carries. */
  readonly scopes: readonly string[]
  /** The resource the tokens are for. */
  readonly resource: string
  /** When the token expires. */
  readonly expiresAt: number
  /** Set once, atomically, by `OAuthStore.useRefreshToken`. */
  readonly usedAt?: number
}

/**
 * Result of `OAuthStore.useRefreshToken`.
 *
 * @example
 * ```ts
 * import type { UsedRefreshToken, OAuthStore } from "@gydr-ai/mcp-oauth"
 *
 * export function markUsed(store: OAuthStore, hash: string): Promise<UsedRefreshToken | undefined> {
 *   return store.useRefreshToken(hash, Date.now())
 * }
 * ```
 */
export interface UsedRefreshToken {
  /** The token record, marked used. */
  readonly record: RefreshTokenRecord
  /**
   * `undefined` for exactly one caller, the one that marked the token used;
   * every later caller sees when that happened.
   */
  readonly previousUsedAt?: number
}
