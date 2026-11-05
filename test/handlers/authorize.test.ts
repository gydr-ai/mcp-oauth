import { describe, expect, it } from "vitest"

import {
  authorizeParams,
  authorizeUrl,
  bindingCookie,
  challengeOf,
  handled,
  ISSUER,
  LOOPBACK,
  newVerifier,
  pageSpy,
  REDIRECT,
  registeredClientId,
  setup,
  without,
} from "../support/harness.js"

async function start(
  params: Record<string, string>,
  h = setup(),
): Promise<Response> {
  return handled(h.auth, new Request(authorizeUrl(params)))
}

function locationOf(response: Response): URL {
  return new URL(response.headers.get("location") ?? "about:blank")
}

describe("GET /authorize — before the client is verified (error pages)", () => {
  it("shows a page for an unknown client, never a redirect", async () => {
    const h = setup()
    const response = await start(
      authorizeParams("client-unknown", newVerifier()),
      h,
    )

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
    expect(response.headers.get("content-type")).toContain("text/html")
    expect(h.events).toContainEqual({
      type: "authorization_refused",
      reason: "client_unknown",
    })
  })

  it("shows a page for a missing client_id", async () => {
    const response = await start(
      without(authorizeParams("x", newVerifier()), "client_id"),
    )

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
  })

  it.each([
    ["https://evil.example/callback"],
    ["https://client.example.org/callback/"],
    ["https://client.example.org/callback?x=1"],
    ["https://client.example.org/callback#"],
    ["javascript:alert(1)"],
  ])("shows a page for an unregistered redirect_uri %s", async (uri) => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const response = await start(
      authorizeParams(clientId, newVerifier(), { redirect_uri: uri }),
      h,
    )

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
  })

  it("uses the only registered redirect_uri when none is sent (OAuth 2.1 § 4.1.1)", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const response = await start(
      without(authorizeParams(clientId, newVerifier()), "redirect_uri"),
      h,
    )

    expect(response.status).toBe(302)
    expect(locationOf(response).origin).toBe("https://idp.example.net")
  })

  it("shows a page for a missing redirect_uri when several are registered", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth, [
      REDIRECT,
      "https://client.example.org/second",
    ])
    const response = await start(
      without(authorizeParams(clientId, newVerifier()), "redirect_uri"),
      h,
    )

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
  })

  it("refuses a duplicated parameter with a page (parser-confusion)", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const url = new URL(authorizeUrl(authorizeParams(clientId, newVerifier())))

    url.searchParams.append("redirect_uri", "https://evil.example/cb")

    const response = await handled(h.auth, new Request(url))

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
  })

  it("sends the strict page headers", async () => {
    const response = await start(authorizeParams("nope", newVerifier()))

    expect(response.headers.get("content-security-policy")).toContain(
      "frame-ancestors 'none'",
    )
    expect(response.headers.get("x-frame-options")).toBe("DENY")
    expect(response.headers.get("cache-control")).toBe("no-store")
    expect(response.headers.get("referrer-policy")).toBe("no-referrer")
  })

  it("shows a 429 page when rate limited", async () => {
    const h = setup({ rateLimit: () => Promise.resolve(false) })
    const response = await start(authorizeParams("x", newVerifier()), h)

    expect(response.status).toBe(429)
  })
})

describe("GET /authorize — after the client is verified (still error pages)", () => {
  // RFC 9700 § 4.11.2 and OAuth 2.1 § 7.13.2: nothing is sent to the
  // client before the person signed in, so an authorization endpoint can
  // never be used as an open redirector or to probe a client's redirect.
  it.each([
    [{ response_type: "token" }, "unsupported_response_type"],
    [{ code_challenge: "short" }, "invalid_request"],
    [{ code_challenge: `${"a".repeat(42)}=` }, "invalid_request"],
    [{ code_challenge_method: "plain" }, "invalid_request"],
    [{ resource: "https://other.example.com/mcp" }, "invalid_target"],
    [{ scope: "admin" }, "invalid_scope"],
    [{ scope: " " }, "invalid_scope"],
    [{ state: "s".repeat(2049) }, "invalid_request"],
    [{ prompt: "none" }, "consent_required"],
  ])(
    "shows a page for %o with reason %s, never a redirect",
    async (extra, reason) => {
      const spy = pageSpy()
      const h = setup({ renderErrorPage: spy.renderErrorPage })
      const clientId = await registeredClientId(h.auth)
      const response = await start(
        authorizeParams(clientId, newVerifier(), extra),
        h,
      )

      expect(response.status).toBeGreaterThanOrEqual(400)
      expect(response.headers.get("location")).toBeNull()
      expect(spy.pages.map((page) => page.reason)).toEqual([reason])
    },
  )

  it("shows a page for missing PKCE and a missing resource", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)

    for (const drop of [
      "code_challenge",
      "code_challenge_method",
      "resource",
    ]) {
      const response = await start(
        without(authorizeParams(clientId, newVerifier()), drop),
        h,
      )

      expect(response.status).toBe(400)
      expect(response.headers.get("location")).toBeNull()
    }
  })

  it("accepts a resource that differs only in scheme and host case", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const response = await start(
      authorizeParams(clientId, newVerifier(), {
        resource: "HTTPS://MCP.Example.com/mcp",
      }),
      h,
    )

    expect(response.status).toBe(302)
    expect(locationOf(response).origin).toBe("https://idp.example.net")
  })

  it("refuses a resource whose path differs in case", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const response = await start(
      authorizeParams(clientId, newVerifier(), {
        resource: "https://mcp.example.com/MCP",
      }),
      h,
    )

    expect(response.status).toBe(400)
  })

  it("ignores unknown parameters, even repeated", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const url = new URL(authorizeUrl(authorizeParams(clientId, newVerifier())))

    url.searchParams.append("x_custom", "1")
    url.searchParams.append("x_custom", "2")

    const response = await handled(h.auth, new Request(url))

    expect(response.status).toBe(302)
    expect(locationOf(response).origin).toBe("https://idp.example.net")
  })

  it("gives the renderer locales from Accept-Language", async () => {
    const spy = pageSpy()
    const h = setup({ renderErrorPage: spy.renderErrorPage })

    await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams("nope", newVerifier())), {
        headers: { "accept-language": "fr-CH, fr;q=0.9, en;q=0.8" },
      }),
    )

    expect(spy.pages[0]?.locales).toEqual(["fr-CH", "fr", "en"])
    expect(spy.pages[0]?.reason).toBe("client_unknown")
  })
})

describe("GET /authorize — success", () => {
  it("stores a pending authorization and goes to the IdP with OUR pkce, state and nonce", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const verifier = newVerifier()
    const response = await start(authorizeParams(clientId, verifier), h)

    expect(response.status).toBe(302)
    expect(locationOf(response).origin).toBe("https://idp.example.net")

    const sent = h.idp.lastAuthorization

    expect(sent?.redirectUri).toBe(`${ISSUER}/callback`)
    // Our own PKCE pair, never the client's challenge.
    expect(sent?.codeChallenge).not.toBe(challengeOf(verifier))
    expect(sent?.state).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(sent?.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const cookie = response.headers.getSetCookie()[0] ?? ""

    expect(cookie).toMatch(/^__Host-mcp-auth-[0-9a-f]{20}=/)
    expect(cookie).toContain("HttpOnly")
    expect(cookie).toContain("Secure")
    expect(cookie).toContain("SameSite=Lax")
    expect(cookie).toContain("Path=/")
    expect(cookie).not.toContain("Domain")
    expect(h.events).toContainEqual({
      type: "authorization_started",
      clientId,
      scopes: ["mcp"],
    })
  })

  it("accepts a loopback redirect on any port", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth, [LOOPBACK])
    const response = await start(
      authorizeParams(clientId, newVerifier(), {
        redirect_uri: "http://127.0.0.1:49152/callback",
      }),
      h,
    )

    expect(response.status).toBe(302)
    expect(bindingCookie(response)).toContain("__Host-")
  })

  it("accepts a statically stored client", async () => {
    const h = setup()

    await h.store.putClient({
      clientId: "static-client",
      redirectUris: [REDIRECT],
      kind: "static",
      createdAt: 0,
    })

    const response = await start(
      authorizeParams("static-client", newVerifier()),
      h,
    )

    expect(response.status).toBe(302)
    expect(locationOf(response).origin).toBe("https://idp.example.net")
  })

  it("refuses a stored record pretending to be a metadata-document client", async () => {
    const h = setup()

    await h.store.putClient({
      clientId: "spoof",
      redirectUris: [REDIRECT],
      kind: "metadata_document",
      createdAt: 0,
    })

    const response = await start(authorizeParams("spoof", newVerifier()), h)

    expect(response.status).toBe(400)
  })
})
