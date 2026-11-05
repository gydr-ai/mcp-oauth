import { describe, expect, it } from "vitest"

import {
  authorizeParams,
  authorizeUrl,
  bindingCookie,
  connect,
  errorOf,
  handled,
  ISSUER,
  mcpRequest,
  newVerifier,
  pageSpy,
  REDIRECT,
  registerClient,
  registeredClientId,
  RESOURCE,
  setup,
} from "../support/harness.js"

describe("bearer challenge (RFC 6750 § 3.1)", () => {
  it.each([["Basic YTpi"], ["DPoP abc"], ["Digest x"]])(
    "answers %s (no Bearer credentials) with the bare challenge",
    async (value) => {
      const h = setup()
      const result = await h.auth.authenticate(
        new Request(RESOURCE, { headers: { Authorization: value } }),
      )

      if (result.ok) throw new Error("expected failure")

      const header = result.response.headers.get("www-authenticate") ?? ""

      expect(result.response.status).toBe(401)
      expect(header).toMatch(/^Bearer resource_metadata=/)
      expect(header).not.toContain("error=")
    },
  )

  it("still reports invalid_token for a bad Bearer value", async () => {
    const h = setup()
    const result = await h.auth.authenticate(mcpRequest("A".repeat(43)))

    if (result.ok) throw new Error("expected failure")

    expect(result.response.headers.get("www-authenticate")).toContain(
      'error="invalid_token"',
    )
  })
})

describe("redirect URIs that already carry response parameters", () => {
  it.each([
    ["code"],
    ["state"],
    ["iss"],
    ["error"],
    ["error_description"],
    ["error_uri"],
  ])("are refused at registration (%s)", async (name) => {
    const h = setup()
    const response = await registerClient(h.auth, {
      redirect_uris: [`${REDIRECT}?${name}=forged`],
    })

    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe("invalid_redirect_uri")
  })

  it("allow other query parameters", async () => {
    const h = setup()
    const response = await registerClient(h.auth, {
      redirect_uris: [`${REDIRECT}?tenant=a`],
    })

    expect(response.status).toBe(201)
  })
})

describe("revocation endpoint request shape", () => {
  function revoke(body: URLSearchParams, headers: Record<string, string> = {}) {
    return new Request(`${ISSUER}/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...headers,
      },
      body: body.toString(),
    })
  }

  it("ignores repeated unknown parameters and refuses a repeated token", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const fine = new URLSearchParams({ token: pair.refresh_token })

    fine.append("x_extra", "1")
    fine.append("x_extra", "2")
    expect((await handled(h.auth, revoke(fine))).status).toBe(200)
    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      false,
    )

    const twice = new URLSearchParams({ token: "a" })

    twice.append("token", "b")
    expect(await errorOf(await handled(h.auth, revoke(twice)))).toBe(
      "invalid_request",
    )
  })

  it("answers an Authorization header with 401 and a challenge in its scheme", async () => {
    const h = setup()
    const response = await handled(
      h.auth,
      revoke(new URLSearchParams({ token: "a" }), {
        Authorization: "Basic YTpi",
      }),
    )

    expect(response.status).toBe(401)
    expect(response.headers.get("www-authenticate")).toBe("Basic")
  })

  it("answers a body client_secret with 400 invalid_client", async () => {
    const h = setup()
    const response = await handled(
      h.auth,
      revoke(new URLSearchParams({ token: "a", client_secret: "s" })),
    )

    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe("invalid_client")
  })
})

describe("policy reasons reach the error page", () => {
  it("authorizeClient { allow: false, reason } shows a 403 page with policyReason", async () => {
    const spy = pageSpy()
    const h = setup({
      renderErrorPage: spy.renderErrorPage,
      authorizeClient: () => ({ allow: false, reason: "client_blocked" }),
    })
    const clientId = await registeredClientId(h.auth)
    const response = await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    )

    expect(response.status).toBe(403)
    expect(spy.pages[0]).toMatchObject({
      reason: "access_denied",
      policyReason: "client_blocked",
    })
    expect(Object.isFrozen(spy.pages[0])).toBe(true)
  })

  it("drops a malformed reason but still refuses", async () => {
    const spy = pageSpy()
    const h = setup({
      renderErrorPage: spy.renderErrorPage,
      authorizeClient: () => ({ allow: false, reason: "<script>" }),
    })
    const clientId = await registeredClientId(h.auth)
    const response = await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    )

    expect(response.status).toBe(403)
    expect(spy.pages[0]?.policyReason).toBeUndefined()
  })

  it("{ allow: true } allows, as true does", async () => {
    const h = setup({ authorizeClient: () => ({ allow: true }) })
    const clientId = await registeredClientId(h.auth)
    const response = await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    )

    expect(response.status).toBe(302)
  })

  it("allowSubject { allow: false, reason } shows subject_not_permitted with the reason", async () => {
    const spy = pageSpy()
    const h = setup({
      renderErrorPage: spy.renderErrorPage,
      allowSubject: () => ({ allow: false, reason: "email_unverified" }),
    })
    const clientId = await registeredClientId(h.auth)
    const start = await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    )
    const state = h.idp.lastAuthorization?.state ?? ""
    const code = h.idp.approveLogin()
    const response = await handled(
      h.auth,
      new Request(`${ISSUER}/callback?state=${state}&code=${code}`, {
        headers: { Cookie: bindingCookie(start) },
      }),
    )

    expect(response.status).toBe(403)
    expect(spy.pages.at(-1)).toMatchObject({
      reason: "subject_not_permitted",
      policyReason: "email_unverified",
    })
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })
})

describe("dynamic client registration switch", () => {
  it("can be turned off in one line", async () => {
    const h = setup({ dynamicClientRegistration: false })
    const response = await h.auth.handle(
      new Request(`${ISSUER}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ redirect_uris: [REDIRECT] }),
      }),
    )

    expect(response?.status ?? 404).toBe(404)
  })
})
