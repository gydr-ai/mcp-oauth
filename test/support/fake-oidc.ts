import { createHash } from "node:crypto"

import {
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  type JWTPayload,
  SignJWT,
  UnsecuredJWT,
} from "jose"

export const IDP = "https://idp.example.net"

export interface FakeOidcOptions {
  /** Override claims in the next ID tokens. */
  claims?: JWTPayload
  /** Sign with this algorithm instead of ES256 ("none" / "HS256" for attacks). */
  signWith?: "ES256" | "none" | "HS256"
  discovery?: Record<string, unknown>
  rotateRefreshTokens?: boolean
  omitIdToken?: boolean
  tokenStatus?: number
}

/**
 * A minimal in-process OpenID Connect provider reached through an injected
 * `fetch`: discovery, JWKS, authorization code + PKCE, refresh, revocation.
 */
export class FakeOidc {
  options: FakeOidcOptions = {}
  readonly requests: { url: string; body: string; headers: Headers }[] = []
  readonly revoked: string[] = []
  #key: CryptoKey | undefined
  #jwk: Record<string, unknown> = {}
  readonly #codes = new Map<
    string,
    { challenge: string; nonce: string; redirectUri: string }
  >()
  #counter = 0

  async init(): Promise<this> {
    const { privateKey, publicKey } = await generateKeyPair("ES256")

    this.#key = privateKey
    this.#jwk = { ...(await exportJWK(publicKey)), kid: "key-1", alg: "ES256" }

    return this
  }

  /** Simulate a login for an authorization URL; returns the callback query. */
  login(authorizationUrl: string): URLSearchParams {
    const url = new URL(authorizationUrl)
    const code = `code-${++this.#counter}`

    this.#codes.set(code, {
      challenge: url.searchParams.get("code_challenge") ?? "",
      nonce: url.searchParams.get("nonce") ?? "",
      redirectUri: url.searchParams.get("redirect_uri") ?? "",
    })

    return new URLSearchParams({
      code,
      state: url.searchParams.get("state") ?? "",
      iss: IDP,
    })
  }

  async #idToken(nonce: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000)
    const claims: JWTPayload = {
      iss: IDP,
      aud: "mcp-gateway",
      iat: now,
      exp: now + 300,
      sub: "person-42",
      email: "pat@example.net",
      nonce,
      ...this.options.claims,
    }
    const alg = this.options.signWith ?? "ES256"

    if (alg === "none") return new UnsecuredJWT(claims).encode()

    if (alg === "HS256") {
      return new SignJWT(claims)
        .setProtectedHeader({ alg: "HS256", kid: "key-1" })
        .sign(new TextEncoder().encode("x".repeat(32)))
    }

    if (this.#key === undefined) throw new Error("init() first")

    return new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: "key-1" })
      .sign(this.#key)
  }

  readonly fetch: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input.toString())
    const body = typeof init?.body === "string" ? init.body : ""

    this.requests.push({
      url: url.toString(),
      body,
      headers: new Headers(init?.headers),
    })

    const json = (status: number, value: unknown) =>
      new Response(JSON.stringify(value), {
        status,
        headers: { "Content-Type": "application/json" },
      })

    switch (url.pathname) {
      case "/.well-known/openid-configuration":
        return json(200, {
          issuer: IDP,
          authorization_endpoint: `${IDP}/authorize`,
          token_endpoint: `${IDP}/token`,
          jwks_uri: `${IDP}/jwks`,
          revocation_endpoint: `${IDP}/revoke`,
          code_challenge_methods_supported: ["S256"],
          ...this.options.discovery,
        })
      case "/jwks":
        return json(200, { keys: [this.#jwk] })
      case "/revoke":
        this.revoked.push(new URLSearchParams(body).get("token") ?? "")

        return new Response(null, { status: 200 })
      case "/token":
        return this.#token(new URLSearchParams(body), json)
      default:
        return new Response("not found", { status: 404 })
    }
  }

  async #token(
    form: URLSearchParams,
    json: (status: number, value: unknown) => Response,
  ): Promise<Response> {
    if (this.options.tokenStatus !== undefined) {
      return json(this.options.tokenStatus, { error: "invalid_grant" })
    }

    if (form.get("grant_type") === "refresh_token") {
      if (!(form.get("refresh_token") ?? "").startsWith("idp-refresh-")) {
        return json(400, { error: "invalid_grant" })
      }

      const n = ++this.#counter

      return json(200, {
        access_token: `idp-access-${n}`,
        token_type: "Bearer",
        expires_in: 600,
        ...(this.options.rotateRefreshTokens
          ? { refresh_token: `idp-refresh-${n}` }
          : {}),
      })
    }

    const code = form.get("code") ?? ""
    const issued = this.#codes.get(code)

    this.#codes.delete(code)

    const verifier = form.get("code_verifier") ?? ""
    const challenge = createHash("sha256").update(verifier).digest("base64url")

    if (
      issued === undefined ||
      issued.challenge !== challenge ||
      issued.redirectUri !== form.get("redirect_uri")
    ) {
      return json(400, { error: "invalid_grant" })
    }

    return json(200, {
      access_token: "idp-access-0",
      token_type: "Bearer",
      expires_in: 600,
      refresh_token: "idp-refresh-0",
      ...(this.options.omitIdToken
        ? {}
        : { id_token: await this.#idToken(issued.nonce) }),
    })
  }
}
