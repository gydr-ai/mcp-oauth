/**
 * What a successful sign-in at the identity provider yields.
 *
 * @example
 * ```ts
 * import type {
 *   AuthorizationUrlInput,
 *   ExchangeCodeInput,
 *   IdentityProvider,
 *   UpstreamLogin,
 *   UpstreamTokens,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare function exchangeAtMyIdp(input: ExchangeCodeInput): Promise<UpstreamLogin>
 * declare function refreshAtMyIdp(refreshToken: string): Promise<UpstreamTokens>
 *
 * export const myProvider: IdentityProvider = {
 *   authorizationUrl(input: AuthorizationUrlInput) {
 *     const url = new URL("https://login.example.com/authorize")
 *
 *     url.searchParams.set("state", input.state)
 *     url.searchParams.set("code_challenge", input.codeChallenge)
 *     url.searchParams.set("code_challenge_method", "S256")
 *     url.searchParams.set("redirect_uri", input.redirectUri)
 *     url.searchParams.set("nonce", input.nonce)
 *
 *     return Promise.resolve(url.toString())
 *   },
 *   exchangeCode: (input) => exchangeAtMyIdp(input),
 *   refresh: (refreshToken) => refreshAtMyIdp(refreshToken),
 * }
 * ```
 */
export interface UpstreamLogin {
  /** The person's stable id at the identity provider (OIDC `sub`). */
  readonly subject: string
  /** Human-readable name shown on the consent screen. */
  readonly displayName?: string
  /** Upstream refresh token, kept encrypted on the grant. */
  readonly refreshToken?: string
  /** Upstream access token, kept encrypted on the grant. */
  readonly accessToken?: string
  /** Seconds until `accessToken` expires. */
  readonly expiresIn?: number
  /** Claims about the person, for `mapSubject` and `allowSubject` (for OpenID Connect, the ID token payload). */
  readonly claims?: Readonly<Record<string, unknown>>
}

/**
 * What a successful upstream token renewal yields.
 *
 * @example
 * ```ts
 * import type {
 *   AuthorizationUrlInput,
 *   ExchangeCodeInput,
 *   IdentityProvider,
 *   UpstreamLogin,
 *   UpstreamTokens,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare function exchangeAtMyIdp(input: ExchangeCodeInput): Promise<UpstreamLogin>
 * declare function refreshAtMyIdp(refreshToken: string): Promise<UpstreamTokens>
 *
 * export const myProvider: IdentityProvider = {
 *   authorizationUrl(input: AuthorizationUrlInput) {
 *     const url = new URL("https://login.example.com/authorize")
 *
 *     url.searchParams.set("state", input.state)
 *     url.searchParams.set("code_challenge", input.codeChallenge)
 *     url.searchParams.set("code_challenge_method", "S256")
 *     url.searchParams.set("redirect_uri", input.redirectUri)
 *     url.searchParams.set("nonce", input.nonce)
 *
 *     return Promise.resolve(url.toString())
 *   },
 *   exchangeCode: (input) => exchangeAtMyIdp(input),
 *   refresh: (refreshToken) => refreshAtMyIdp(refreshToken),
 * }
 * ```
 */
export interface UpstreamTokens {
  /** The new upstream access token. */
  readonly accessToken: string
  /** Seconds until `accessToken` expires. */
  readonly expiresIn: number
  /** A new refresh token, when the identity provider rotates them. */
  readonly refreshToken?: string
}

/**
 * Which grant an upstream renewal is for.
 *
 * @example
 * ```ts
 * import type { UpstreamRenewalContext } from "@gydr-ai/mcp-oauth"
 *
 * export function logRenewal(context: UpstreamRenewalContext): string {
 *   return `renewing ${context.grantId} for ${context.subject}`
 * }
 * ```
 */
export interface UpstreamRenewalContext {
  /** The grant whose upstream token is renewed. */
  readonly grantId: string
  /** The person the grant belongs to. */
  readonly subject: string
}

/**
 * Input to {@link IdentityProvider.authorizationUrl}.
 *
 * @example
 * ```ts
 * import type {
 *   AuthorizationUrlInput,
 *   ExchangeCodeInput,
 *   IdentityProvider,
 *   UpstreamLogin,
 *   UpstreamTokens,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare function exchangeAtMyIdp(input: ExchangeCodeInput): Promise<UpstreamLogin>
 * declare function refreshAtMyIdp(refreshToken: string): Promise<UpstreamTokens>
 *
 * export const myProvider: IdentityProvider = {
 *   authorizationUrl(input: AuthorizationUrlInput) {
 *     const url = new URL("https://login.example.com/authorize")
 *
 *     url.searchParams.set("state", input.state)
 *     url.searchParams.set("code_challenge", input.codeChallenge)
 *     url.searchParams.set("code_challenge_method", "S256")
 *     url.searchParams.set("redirect_uri", input.redirectUri)
 *     url.searchParams.set("nonce", input.nonce)
 *
 *     return Promise.resolve(url.toString())
 *   },
 *   exchangeCode: (input) => exchangeAtMyIdp(input),
 *   refresh: (refreshToken) => refreshAtMyIdp(refreshToken),
 * }
 * ```
 */
export interface AuthorizationUrlInput {
  /** The flow id to carry as `state`. */
  readonly state: string
  /** This server's S256 code challenge. */
  readonly codeChallenge: string
  /** The callback URL the provider must return to. */
  readonly redirectUri: string
  /** The OpenID Connect nonce to bind into the ID token. */
  readonly nonce: string
}

/**
 * Input to {@link IdentityProvider.exchangeCode}.
 *
 * @example
 * ```ts
 * import type {
 *   AuthorizationUrlInput,
 *   ExchangeCodeInput,
 *   IdentityProvider,
 *   UpstreamLogin,
 *   UpstreamTokens,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare function exchangeAtMyIdp(input: ExchangeCodeInput): Promise<UpstreamLogin>
 * declare function refreshAtMyIdp(refreshToken: string): Promise<UpstreamTokens>
 *
 * export const myProvider: IdentityProvider = {
 *   authorizationUrl(input: AuthorizationUrlInput) {
 *     const url = new URL("https://login.example.com/authorize")
 *
 *     url.searchParams.set("state", input.state)
 *     url.searchParams.set("code_challenge", input.codeChallenge)
 *     url.searchParams.set("code_challenge_method", "S256")
 *     url.searchParams.set("redirect_uri", input.redirectUri)
 *     url.searchParams.set("nonce", input.nonce)
 *
 *     return Promise.resolve(url.toString())
 *   },
 *   exchangeCode: (input) => exchangeAtMyIdp(input),
 *   refresh: (refreshToken) => refreshAtMyIdp(refreshToken),
 * }
 * ```
 */
export interface ExchangeCodeInput {
  /** The code the identity provider returned. */
  readonly code: string
  /** This server's PKCE verifier. */
  readonly codeVerifier: string
  /** The callback URL used in the authorization request. */
  readonly redirectUri: string
  /** The nonce sent in the authorization request. */
  readonly nonce: string
  /** The RFC 9207 `iss` parameter of the callback, if present. */
  readonly issuer?: string
}

/**
 * The operator's identity provider. `createOidcProvider` implements it for
 * any OpenID Connect provider.
 *
 * @example
 * ```ts
 * import type {
 *   AuthorizationUrlInput,
 *   ExchangeCodeInput,
 *   IdentityProvider,
 *   UpstreamLogin,
 *   UpstreamTokens,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare function exchangeAtMyIdp(input: ExchangeCodeInput): Promise<UpstreamLogin>
 * declare function refreshAtMyIdp(refreshToken: string): Promise<UpstreamTokens>
 *
 * export const myProvider: IdentityProvider = {
 *   authorizationUrl(input: AuthorizationUrlInput) {
 *     const url = new URL("https://login.example.com/authorize")
 *
 *     url.searchParams.set("state", input.state)
 *     url.searchParams.set("code_challenge", input.codeChallenge)
 *     url.searchParams.set("code_challenge_method", "S256")
 *     url.searchParams.set("redirect_uri", input.redirectUri)
 *     url.searchParams.set("nonce", input.nonce)
 *
 *     return Promise.resolve(url.toString())
 *   },
 *   exchangeCode: (input) => exchangeAtMyIdp(input),
 *   refresh: (refreshToken) => refreshAtMyIdp(refreshToken),
 * }
 * ```
 */
export interface IdentityProvider {
  /**
   * The URL to send the browser to. It must carry `state`, the S256
   * `codeChallenge`, `redirectUri` and (for OpenID Connect) `nonce`
   * unchanged.
   */
  authorizationUrl(input: AuthorizationUrlInput): Promise<string>
  /**
   * Exchange the provider's code. Must verify who the person is (for OpenID
   * Connect: the ID token's signature, issuer, audience, expiry and nonce) and
   * reject on any failure.
   */
  exchangeCode(input: ExchangeCodeInput): Promise<UpstreamLogin>
  /**
   * Obtain a fresh upstream access token; reject on any failure. The second
   * argument says which grant and person the renewal is for (metadata for
   * logging or routing, never a credential); providers written for one
   * argument keep working.
   */
  refresh(
    refreshToken: string,
    context?: UpstreamRenewalContext,
  ): Promise<UpstreamTokens>
  /** Revoke an upstream refresh token. Optional; failures are ignored. */
  revoke?(refreshToken: string): Promise<void>
}
