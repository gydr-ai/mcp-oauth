/**
 * Options for `createOidcProvider`.
 *
 * @example
 * ```ts
 * import { createOidcProvider, type OidcProviderOptions } from "@gydr-ai/mcp-oauth"
 *
 * const options: OidcProviderOptions = {
 *   issuer: "https://login.example.com",
 *   clientId: "mcp-gateway",
 *   scopes: ["openid", "offline_access"],
 *   redirectUri: "https://mcp.example.com/callback",
 *   timeoutMs: 5000,
 * }
 * export const provider = createOidcProvider(options)
 * ```
 */
export interface OidcProviderOptions {
  /** The IdP issuer, exactly as its discovery document states it. */
  readonly issuer: string
  readonly clientId: string
  /** For a confidential client at the IdP (recommended). */
  readonly clientSecret?: string
  /**
   * Scopes requested from the IdP. Must include `openid`. Most IdPs need
   * `offline_access` to return a refresh token.
   */
  readonly scopes: readonly string[]
  /**
   * The callback URL registered at the IdP. Must equal the MCP server's
   * callback endpoint; a mismatch throws at login time.
   */
  readonly redirectUri: string
  /**
   * Additional authorization request parameters, for providers that need a
   * provider-specific switch to return a refresh token. The protocol
   * parameters (state, nonce, PKCE, client_id, redirect_uri, response_type,
   * scope) are set by this library and cannot be overridden.
   */
  readonly extraAuthorizationParams?: Readonly<Record<string, string>>
  /**
   * Accepted ID token signature algorithms. Default: RS256, RS384, RS512,
   * PS256, PS384, PS512, ES256, ES384, ES512, EdDSA. `none` and HMAC
   * (`HS*`) are always refused.
   */
  readonly algorithms?: readonly string[]
  /** Deadline per IdP request. Default 10,000 ms. */
  readonly timeoutMs?: number
  /** Clock skew tolerated on ID token times. Default 60 s. */
  readonly clockToleranceSeconds?: number
  /** Allow an `http://localhost` issuer (development only). */
  readonly allowInsecureLocalhost?: boolean
  /** Custom `fetch` (a proxy agent, tests). Default the global `fetch`. */
  readonly fetch?: typeof fetch
}

/**
 * The fields of an OpenID Connect discovery document this library uses.
 *
 * @internal
 */
export interface Discovery {
  readonly issuer: string
  readonly authorization_endpoint: string
  readonly token_endpoint: string
  readonly jwks_uri: string
  readonly revocation_endpoint?: string
  readonly token_endpoint_auth_methods_supported?: readonly string[]
  readonly authorization_response_iss_parameter_supported?: boolean
  readonly code_challenge_methods_supported?: readonly string[]
}

/**
 * The fields of a token endpoint response this library uses.
 *
 * @internal
 */
export interface TokenEndpointResponse {
  readonly access_token: string
  readonly id_token?: string
  readonly refresh_token?: string
  readonly expires_in?: number
}
