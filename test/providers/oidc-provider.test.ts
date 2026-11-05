import { describe, expect, it } from "vitest"

import {
  createOidcProvider,
  type IdentityProvider,
  IdentityProviderError,
  type OidcProviderOptions,
} from "../../src/index.js"
import { FakeOidc, type FakeOidcOptions, IDP } from "../support/fake-oidc.js"

const CALLBACK = "https://auth.example.com/callback"
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

async function setupIdp(
  overrides: Partial<OidcProviderOptions> = {},
): Promise<{ idp: FakeOidc; provider: IdentityProvider }> {
  const idp = await new FakeOidc().init()
  const provider = createOidcProvider({
    issuer: IDP,
    clientId: "mcp-gateway",
    clientSecret: "gateway-secret",
    scopes: ["openid", "email", "offline_access"],
    redirectUri: CALLBACK,
    fetch: idp.fetch,
    ...overrides,
  })

  return { idp, provider }
}

async function login(
  idp: FakeOidc,
  provider: IdentityProvider,
  nonce = "nonce-1",
  iss: string | null = IDP,
) {
  const url = await provider.authorizationUrl({
    state: "state-1",
    codeChallenge: CHALLENGE,
    redirectUri: CALLBACK,
    nonce,
  })
  const callback = idp.login(url)

  return provider.exchangeCode({
    code: callback.get("code") ?? "",
    codeVerifier: VERIFIER,
    redirectUri: CALLBACK,
    nonce,
    ...(iss !== null ? { issuer: iss } : {}),
  })
}

describe("createOidcProvider", () => {
  it("builds the authorization URL with PKCE S256, state, nonce and scopes", async () => {
    const { provider } = await setupIdp({
      extraAuthorizationParams: { prompt: "login" },
    })
    const url = new URL(
      await provider.authorizationUrl({
        state: "s",
        codeChallenge: CHALLENGE,
        redirectUri: CALLBACK,
        nonce: "n",
      }),
    )

    expect(url.origin + url.pathname).toBe(`${IDP}/authorize`)
    expect(Object.fromEntries(url.searchParams)).toEqual({
      prompt: "login",
      response_type: "code",
      client_id: "mcp-gateway",
      redirect_uri: CALLBACK,
      scope: "openid email offline_access",
      state: "s",
      nonce: "n",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
    })
  })

  it("exchanges a code and verifies the ID token", async () => {
    const { idp, provider } = await setupIdp()
    const result = await login(idp, provider)

    expect(result).toMatchObject({
      subject: "person-42",
      displayName: "pat@example.net",
      accessToken: "idp-access-0",
      refreshToken: "idp-refresh-0",
      expiresIn: 600,
    })
    expect(result.claims).toMatchObject({
      sub: "person-42",
      email: "pat@example.net",
      nonce: "nonce-1",
    })

    const token = idp.requests.find((r) => r.url === `${IDP}/token`)

    expect(token?.headers.get("authorization")).toMatch(/^Basic /)
    expect(token?.body).not.toContain("client_secret")
  })

  it("uses client_secret_post when that is all the IdP supports", async () => {
    const { idp, provider } = await setupIdp()

    idp.options = {
      discovery: {
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      },
    }
    await login(idp, provider)

    const token = idp.requests.find((r) => r.url === `${IDP}/token`)

    expect(token?.body).toContain("client_secret=gateway-secret")
    expect(token?.headers.get("authorization")).toBeNull()
  })

  it("refuses when the IdP supports no secret method we know", async () => {
    const { idp, provider } = await setupIdp()

    idp.options = {
      discovery: { token_endpoint_auth_methods_supported: ["private_key_jwt"] },
    }
    await expect(login(idp, provider)).rejects.toThrow(IdentityProviderError)
  })

  it("works as a public client without a secret", async () => {
    const idp = await new FakeOidc().init()
    const provider = createOidcProvider({
      issuer: IDP,
      clientId: "mcp-gateway",
      scopes: ["openid"],
      redirectUri: CALLBACK,
      fetch: idp.fetch,
    })

    expect((await login(idp, provider)).subject).toBe("person-42")
  })

  it.each([
    ["a wrong nonce", {}, "other-nonce"],
    ["a wrong audience", { claims: { aud: "someone-else" } }, undefined],
    ["a wrong issuer", { claims: { iss: "https://evil.example" } }, undefined],
    ["an expired token", { claims: { exp: 1 } }, undefined],
    ["alg none", { signWith: "none" }, undefined],
    ["an HMAC token", { signWith: "HS256" }, undefined],
    ["a foreign azp", { claims: { azp: "other" } }, undefined],
    [
      "multiple audiences without azp",
      { claims: { aud: ["mcp-gateway", "x"] } },
      undefined,
    ],
    ["a missing ID token", { omitIdToken: true }, undefined],
  ] satisfies [string, FakeOidcOptions, string | undefined][])(
    "rejects %s",
    async (_name, options, nonce) => {
      const { idp, provider } = await setupIdp()

      idp.options = { ...options }

      const url = await provider.authorizationUrl({
        state: "s",
        codeChallenge: CHALLENGE,
        redirectUri: CALLBACK,
        nonce: "nonce-1",
      })
      const code = idp.login(url).get("code") ?? ""

      await expect(
        provider.exchangeCode({
          code,
          codeVerifier: VERIFIER,
          redirectUri: CALLBACK,
          nonce: nonce ?? "nonce-1",
          issuer: IDP,
        }),
      ).rejects.toThrow(IdentityProviderError)
    },
  )

  it("enforces RFC 9207 iss when sent or promised", async () => {
    const { idp, provider } = await setupIdp()

    await expect(
      login(idp, provider, "n", "https://evil.example"),
    ).rejects.toThrow("iss")

    idp.options = {
      discovery: { authorization_response_iss_parameter_supported: true },
    }

    const fresh = await setupIdp()

    fresh.idp.options = idp.options
    await expect(login(fresh.idp, fresh.provider, "n", null)).rejects.toThrow(
      "omits the promised iss",
    )
  })

  it("refreshes, passing a rotated refresh token through", async () => {
    const { idp, provider } = await setupIdp()

    idp.options = { rotateRefreshTokens: true }

    const tokens = await provider.refresh("idp-refresh-0")

    expect(tokens.accessToken).toMatch(/^idp-access-/)
    expect(tokens.refreshToken).toMatch(/^idp-refresh-/)
    expect(tokens.expiresIn).toBe(600)
  })

  it("surfaces an IdP error code without the token", async () => {
    const { idp, provider } = await setupIdp()

    idp.options = { tokenStatus: 400 }

    const error = await provider
      .refresh("idp-refresh-0")
      .catch((e: unknown) => e)

    expect(error).toBeInstanceOf(IdentityProviderError)
    expect(error).toHaveProperty("code", "invalid_grant")
    expect(String(error)).not.toContain("idp-refresh-0")
  })

  it("revokes at the revocation endpoint", async () => {
    const { idp, provider } = await setupIdp()

    await provider.revoke?.("idp-refresh-0")
    expect(idp.revoked).toEqual(["idp-refresh-0"])
  })

  it("skips revocation when the IdP has no endpoint", async () => {
    const { idp, provider } = await setupIdp()

    idp.options = { discovery: { revocation_endpoint: undefined } }
    await provider.revoke?.("idp-refresh-0")
    expect(idp.revoked).toEqual([])
  })

  it("refuses a discovery document naming another issuer, then retries", async () => {
    const { idp, provider } = await setupIdp()

    idp.options = { discovery: { issuer: "https://evil.example" } }
    await expect(provider.refresh("idp-refresh-0")).rejects.toThrow("issuer")

    idp.options = {}
    await expect(provider.refresh("idp-refresh-0")).resolves.toBeDefined()
  })

  it.each([
    [{ token_endpoint: "http://idp.example.net/token" }, "https"],
    [{ code_challenge_methods_supported: ["plain"] }, "S256"],
    [{ jwks_uri: 5 }, "lacks required fields"],
  ])("refuses discovery %o", async (discovery, message) => {
    const { idp, provider } = await setupIdp()

    idp.options = { discovery }
    await expect(provider.refresh("idp-refresh-0")).rejects.toThrow(message)
  })

  it("refuses a failing or unreachable discovery", async () => {
    const down = createOidcProvider({
      issuer: IDP,
      clientId: "c",
      scopes: ["openid"],
      redirectUri: CALLBACK,
      fetch: () => Promise.resolve(new Response("", { status: 503 })),
    })

    await expect(down.refresh("x")).rejects.toThrow("HTTP 503")

    const unreachable = createOidcProvider({
      issuer: IDP,
      clientId: "c",
      scopes: ["openid"],
      redirectUri: CALLBACK,
      fetch: () => Promise.reject(new TypeError("fetch failed")),
    })

    await expect(unreachable.refresh("x")).rejects.toThrow("Could not reach")
  })

  it("refuses a mismatched callback URL", async () => {
    const { provider } = await setupIdp()

    await expect(
      provider.authorizationUrl({
        state: "s",
        codeChallenge: CHALLENGE,
        redirectUri: "https://other.example/callback",
        nonce: "n",
      }),
    ).rejects.toThrow("redirectUri")
  })

  it("validates its configuration", () => {
    const base = {
      issuer: IDP,
      clientId: "c",
      scopes: ["openid"],
      redirectUri: CALLBACK,
    }

    expect(() => createOidcProvider({ ...base, scopes: ["email"] })).toThrow(
      TypeError,
    )
    expect(() =>
      createOidcProvider({ ...base, algorithms: ["HS256"] }),
    ).toThrow(TypeError)
    expect(() => createOidcProvider({ ...base, algorithms: ["none"] })).toThrow(
      TypeError,
    )
    expect(() => createOidcProvider({ ...base, algorithms: [] })).toThrow(
      TypeError,
    )
    expect(() =>
      createOidcProvider({ ...base, extraAuthorizationParams: { state: "x" } }),
    ).toThrow(TypeError)
    expect(() =>
      createOidcProvider({ ...base, issuer: "http://idp.example.net" }),
    ).toThrow(TypeError)
    expect(() =>
      createOidcProvider({
        ...base,
        issuer: "http://localhost:8080",
        allowInsecureLocalhost: true,
      }),
    ).not.toThrow()
    expect(() => createOidcProvider({ ...base, issuer: "nope" })).toThrow(
      TypeError,
    )
  })
})
