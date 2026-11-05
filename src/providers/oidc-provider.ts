import { trimTrailing } from "../helpers/text.js"
import {
  createRemoteJWKSet,
  customFetch,
  type JWTPayload,
  jwtVerify,
} from "jose"

import { DEFAULT_ALGORITHMS, RESERVED_PARAMS } from "../constants/oidc.js"
import { IdentityProviderError } from "../errors/identity-provider-error.js"
import { isRecord } from "../helpers/guards.js"
import type {
  IdentityProvider,
  UpstreamLogin,
  UpstreamTokens,
} from "../interfaces/identity-provider.js"
import type {
  Discovery,
  OidcProviderOptions,
  TokenEndpointResponse,
} from "../interfaces/oidc.js"
import {
  checkEndpoint,
  isDiscovery,
  isTokenResponse,
} from "./oidc-documents.js"

/**
 * An {@link IdentityProvider} for any OpenID Connect provider: discovery,
 * authorization code + PKCE S256 + nonce, and ID token verification (`iss`,
 * `aud`, `azp`, `exp`, `nonce`, signature against the IdP's JWKS with an
 * asymmetric-only algorithm allow-list).
 *
 * IdP requests use plain `fetch` with a timeout: the issuer is configured
 * by the operator and may legitimately sit on a private network.
 *
 * @param options - The provider's issuer, this server's client credentials,
 *   scopes and callback URL.
 * @returns An `IdentityProvider`; discovery runs lazily on first use and is retried after a failure.
 * @throws {TypeError} When `scopes` lacks `openid`, an algorithm is not
 *   asymmetric, a reserved parameter is overridden, or the issuer is not an
 *   `https` URL.
 * @example
 * ```ts
 * import { createOidcProvider } from "@gydr-ai/mcp-oauth"
 *
 * export const identityProvider = createOidcProvider({
 *   issuer: "https://login.example.com",
 *   clientId: "mcp-gateway",
 *   clientSecret: process.env.OIDC_CLIENT_SECRET ?? "",
 *   scopes: ["openid", "email", "offline_access"],
 *   redirectUri: "https://mcp.example.com/callback",
 * })
 * ```
 */
export function createOidcProvider(
  options: OidcProviderOptions,
): IdentityProvider {
  const insecure = options.allowInsecureLocalhost === true
  const timeoutMs = options.timeoutMs ?? 10_000
  const doFetch = options.fetch ?? fetch
  const algorithms = [...(options.algorithms ?? DEFAULT_ALGORITHMS)]

  if (!options.scopes.includes("openid")) {
    throw new TypeError("OIDC scopes need to contain openid")
  }

  if (
    algorithms.length === 0 ||
    algorithms.some(
      (alg) =>
        alg.toLowerCase() === "none" || alg.toUpperCase().startsWith("HS"),
    )
  ) {
    throw new TypeError(
      "Only asymmetric signature algorithms are allowed (no none, no HS*)",
    )
  }

  for (const key of Object.keys(options.extraAuthorizationParams ?? {})) {
    if (RESERVED_PARAMS.has(key)) {
      throw new TypeError(`extraAuthorizationParams may not override ${key}`)
    }
  }

  try {
    checkEndpoint("issuer", options.issuer, insecure)
  } catch (error) {
    throw new TypeError(
      error instanceof Error
        ? error.message
        : "Identity provider issuer is not usable",
    )
  }

  const timedFetch = (url: string | URL, init: RequestInit = {}) =>
    doFetch(url, {
      ...init,
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    })

  let discovery: Promise<{
    readonly document: Discovery
    readonly jwks: ReturnType<typeof createRemoteJWKSet>
  }> | null = null

  const discover = () => {
    if (discovery !== null) return discovery

    const running = (async () => {
      const base = trimTrailing(options.issuer, "/")
      let response: Response

      try {
        response = await timedFetch(
          `${base}/.well-known/openid-configuration`,
          {
            headers: { Accept: "application/json" },
          },
        )
      } catch (error) {
        throw new IdentityProviderError(
          "Could not reach the identity provider's discovery document",
          undefined,
          {
            cause: error,
          },
        )
      }

      if (!response.ok) {
        throw new IdentityProviderError(
          `Discovery document request returned HTTP ${response.status}`,
        )
      }

      const document: unknown = await response.json().catch(() => undefined)

      if (!isDiscovery(document)) {
        throw new IdentityProviderError(
          "Discovery document lacks required fields",
        )
      }

      // OIDC Discovery § 4.3: the document must name the configured issuer.
      if (document.issuer !== options.issuer) {
        throw new IdentityProviderError(
          "Discovery document names a different issuer than configured",
        )
      }

      if (
        document.code_challenge_methods_supported !== undefined &&
        !document.code_challenge_methods_supported.includes("S256")
      ) {
        throw new IdentityProviderError(
          "Identity provider does not offer S256 code challenges",
        )
      }

      checkEndpoint(
        "authorization_endpoint",
        document.authorization_endpoint,
        insecure,
      )
      checkEndpoint("token_endpoint", document.token_endpoint, insecure)

      const jwksUrl = checkEndpoint("jwks_uri", document.jwks_uri, insecure)

      if (document.revocation_endpoint !== undefined) {
        checkEndpoint(
          "revocation_endpoint",
          document.revocation_endpoint,
          insecure,
        )
      }

      const jwks = createRemoteJWKSet(jwksUrl, {
        timeoutDuration: timeoutMs,
        [customFetch]: (url: string, init: RequestInit) =>
          doFetch(url, { ...init, redirect: "error" }),
      })

      return { document, jwks }
    })()

    discovery = running
    // A failed discovery is retried on the next call.
    running.catch(() => {
      if (discovery === running) discovery = null
    })

    return running
  }

  /**
   * Client authentication for the token and revocation endpoints.
   *
   * @param document - The provider's discovery document; its `token_endpoint_auth_methods_supported` picks the method.
   * @param body - Form body of the outgoing request; `client_id` (and, for `client_secret_post`, the secret) are added to it.
   * @returns Headers to add (empty when credentials go in the body).
   */
  const clientAuth = (
    document: Discovery,
    body: URLSearchParams,
  ): Record<string, string> => {
    body.set("client_id", options.clientId)

    if (options.clientSecret === undefined) return {}

    const methods = document.token_endpoint_auth_methods_supported ?? [
      "client_secret_basic",
    ]

    if (methods.includes("client_secret_basic")) {
      // RFC 6749 § 2.3.1: form-encode each part before base64.
      const user = encodeURIComponent(options.clientId)
      const pass = encodeURIComponent(options.clientSecret)

      return {
        Authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`,
      }
    }

    if (methods.includes("client_secret_post")) {
      body.set("client_secret", options.clientSecret)

      return {}
    }

    throw new IdentityProviderError(
      "Identity provider accepts no client-secret method this library implements",
    )
  }

  const postToken = async (
    document: Discovery,
    body: URLSearchParams,
  ): Promise<TokenEndpointResponse> => {
    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      ...clientAuth(document, body),
    }
    let response: Response

    try {
      response = await timedFetch(document.token_endpoint, {
        method: "POST",
        headers,
        body: body.toString(),
      })
    } catch (error) {
      throw new IdentityProviderError(
        "Could not reach the identity provider's token endpoint",
        undefined,
        {
          cause: error,
        },
      )
    }

    const parsed: unknown = await response.json().catch(() => undefined)

    if (!response.ok) {
      const code =
        isRecord(parsed) && typeof parsed.error === "string"
          ? parsed.error.slice(0, 64)
          : undefined

      throw new IdentityProviderError(
        `Token endpoint returned HTTP ${response.status}`,
        code,
      )
    }

    if (!isTokenResponse(parsed)) {
      throw new IdentityProviderError(
        "Token endpoint reply lacks an access_token",
      )
    }

    return parsed
  }

  const verifyIdToken = async (
    document: Discovery,
    jwks: ReturnType<typeof createRemoteJWKSet>,
    idToken: string,
    nonce: string,
  ): Promise<JWTPayload> => {
    let payload: JWTPayload

    try {
      ;({ payload } = await jwtVerify(idToken, jwks, {
        issuer: document.issuer,
        audience: options.clientId,
        algorithms,
        clockTolerance: options.clockToleranceSeconds ?? 60,
        requiredClaims: ["sub", "exp", "iat"],
      }))
    } catch (error) {
      throw new IdentityProviderError(
        "ID token signature or claims did not verify",
        undefined,
        { cause: error },
      )
    }

    if (payload.nonce !== nonce) {
      throw new IdentityProviderError(
        "ID token nonce differs from the one sent",
      )
    }

    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud]

    if (
      (audiences.length > 1 || payload.azp !== undefined) &&
      payload.azp !== options.clientId
    ) {
      throw new IdentityProviderError("ID token azp names some other client")
    }

    return payload
  }

  return {
    async authorizationUrl({ state, codeChallenge, redirectUri, nonce }) {
      if (redirectUri !== options.redirectUri) {
        throw new IdentityProviderError(
          "Callback URL differs from the redirectUri this provider was configured with",
        )
      }

      const { document } = await discover()
      const url = new URL(document.authorization_endpoint)

      for (const [key, value] of Object.entries(
        options.extraAuthorizationParams ?? {},
      )) {
        url.searchParams.set(key, value)
      }

      url.searchParams.set("response_type", "code")
      url.searchParams.set("client_id", options.clientId)
      url.searchParams.set("redirect_uri", redirectUri)
      url.searchParams.set("scope", options.scopes.join(" "))
      url.searchParams.set("state", state)
      url.searchParams.set("nonce", nonce)
      url.searchParams.set("code_challenge", codeChallenge)
      url.searchParams.set("code_challenge_method", "S256")

      return url.toString()
    },

    async exchangeCode({ code, codeVerifier, redirectUri, nonce, issuer }) {
      const { document, jwks } = await discover()

      // RFC 9207: when the IdP sends `iss` it must be the expected issuer;
      // when it promises to send it, it must be there (mix-up defence).
      if (issuer !== undefined && issuer !== document.issuer) {
        throw new IdentityProviderError(
          "Authorization response iss names another issuer",
        )
      }

      if (
        issuer === undefined &&
        document.authorization_response_iss_parameter_supported === true
      ) {
        throw new IdentityProviderError(
          "Authorization response omits the promised iss",
        )
      }

      const tokens = await postToken(
        document,
        new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }),
      )

      if (tokens.id_token === undefined) {
        throw new IdentityProviderError("Token endpoint reply has no id_token")
      }

      const claims = await verifyIdToken(document, jwks, tokens.id_token, nonce)
      const subject = claims.sub

      if (typeof subject !== "string" || subject === "") {
        throw new IdentityProviderError("ID token carries no sub claim")
      }

      const displayName = [
        claims.name,
        claims.email,
        claims.preferred_username,
      ].find(
        (value): value is string => typeof value === "string" && value !== "",
      )
      const login: UpstreamLogin = {
        subject,
        claims: { ...claims },
        accessToken: tokens.access_token,
        expiresIn: tokens.expires_in ?? 300,
        ...(displayName !== undefined ? { displayName } : {}),
        ...(tokens.refresh_token !== undefined
          ? { refreshToken: tokens.refresh_token }
          : {}),
      }

      return login
    },

    async refresh(refreshToken): Promise<UpstreamTokens> {
      const { document } = await discover()
      const tokens = await postToken(
        document,
        new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
      )

      return {
        accessToken: tokens.access_token,
        expiresIn: tokens.expires_in ?? 300,
        ...(tokens.refresh_token !== undefined
          ? { refreshToken: tokens.refresh_token }
          : {}),
      }
    },

    async revoke(refreshToken) {
      const { document } = await discover()

      if (document.revocation_endpoint === undefined) return

      const body = new URLSearchParams({
        token: refreshToken,
        token_type_hint: "refresh_token",
      })
      const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        ...clientAuth(document, body),
      }

      try {
        await timedFetch(document.revocation_endpoint, {
          method: "POST",
          headers,
          body: body.toString(),
        })
      } catch (error) {
        throw new IdentityProviderError(
          "Could not reach the identity provider's revocation endpoint",
          undefined,
          {
            cause: error,
          },
        )
      }
    },
  }
}
