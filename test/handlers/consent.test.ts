import { describe, expect, it } from "vitest"

import {
  authorizeParams,
  authorizeUrl,
  bindingCookie,
  consentRequest,
  handled,
  ISSUER,
  newVerifier,
  REDIRECT,
  reachConsent,
  registerClient,
  registeredClientId,
  setup,
} from "../support/harness.js"

async function begin(h = setup()) {
  const clientId = await registeredClientId(h.auth)
  const response = await handled(
    h.auth,
    new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
  )

  return {
    h,
    clientId,
    cookie: bindingCookie(response),
    state: h.idp.lastAuthorization?.state ?? "",
  }
}

function callback(query: string, cookie?: string): Request {
  return new Request(`${ISSUER}/callback?${query}`, {
    headers: cookie === undefined ? {} : { Cookie: cookie },
  })
}

describe("GET /callback", () => {
  it("shows an escaped approval screen with a form token", async () => {
    const h = setup()
    const response = await registerClient(h.auth, {
      redirect_uris: [REDIRECT],
      client_name: '<script>alert("x")</script>',
    })
    const body: unknown = await response.json()
    const clientId =
      typeof body === "object" && body !== null && "client_id" in body
        ? String(body.client_id)
        : ""

    h.idp.login = { displayName: "<b>Pat</b>" }

    const screen = await reachConsent(h, clientId, newVerifier())

    expect(screen.response.status).toBe(200)
    expect(screen.html).not.toContain("<script>")
    expect(screen.html).toContain("&lt;script&gt;")
    expect(screen.html).toContain("&lt;b&gt;Pat&lt;/b&gt;")
    expect(screen.html).toContain("Self-registered application")
    expect(screen.html).toContain("client.example.org")
    expect(screen.csrf).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const csp = screen.response.headers.get("content-security-policy") ?? ""

    expect(csp).toContain("default-src 'none'")
    expect(csp).toContain("form-action 'self' https://client.example.org")
    expect(csp).toContain("frame-ancestors 'none'")
    expect(screen.response.headers.get("x-frame-options")).toBe("DENY")
    expect(screen.response.headers.get("cache-control")).toBe("no-store")
  })

  it("refuses a callback without the binding cookie (login CSRF)", async () => {
    const { h, state } = await begin()
    const code = h.idp.approveLogin()
    const response = await handled(
      h.auth,
      callback(`state=${state}&code=${code}`),
    )

    expect(response.status).toBe(400)
    expect(await response.text()).toContain("browser where it began")
    expect(h.events).toContainEqual({
      type: "flow_binding_mismatch",
      step: "callback",
    })
  })

  it("refuses a callback with another flow's cookie value", async () => {
    const { h, state, cookie } = await begin()
    const name = cookie.split("=")[0] ?? ""
    const code = h.idp.approveLogin()
    const response = await handled(
      h.auth,
      callback(`state=${state}&code=${code}`, `${name}=forged`),
    )

    expect(response.status).toBe(400)
  })

  it("consumes the pending authorization once (a replay finds nothing)", async () => {
    const { h, state, cookie } = await begin()
    const code = h.idp.approveLogin()
    const first = await handled(
      h.auth,
      callback(`state=${state}&code=${code}`, cookie),
    )

    expect(first.status).toBe(200)

    const replay = await handled(
      h.auth,
      callback(`state=${state}&code=${code}`, cookie),
    )

    expect(replay.status).toBe(400)
    expect(await replay.text()).toContain("no longer open")
  })

  it("refuses an expired pending authorization", async () => {
    const { h, state, cookie } = await begin()
    const code = h.idp.approveLogin()

    h.clock.advance(901)

    const response = await handled(
      h.auth,
      callback(`state=${state}&code=${code}`, cookie),
    )

    expect(response.status).toBe(400)
  })

  it("refuses duplicated params, missing state and missing code", async () => {
    const { h, state, cookie } = await begin()

    expect(
      (await handled(h.auth, callback(`state=${state}&state=x`, cookie)))
        .status,
    ).toBe(400)
    expect((await handled(h.auth, callback("code=x", cookie))).status).toBe(400)

    const missing = await handled(h.auth, callback(`state=${state}`, cookie))

    expect(missing.status).toBe(400)
    expect(missing.headers.get("location")).toBeNull()
  })

  it("forwards an IdP access_denied to the client as access_denied", async () => {
    const { h, state, cookie } = await begin()
    const response = await handled(
      h.auth,
      callback(`state=${state}&error=access_denied`, cookie),
    )
    const location = new URL(response.headers.get("location") ?? "")

    expect(response.status).toBe(302)
    expect(location.searchParams.get("error")).toBe("access_denied")
    expect(location.searchParams.get("state")).toBe("client-state-1")
    expect(location.searchParams.get("iss")).toBe(ISSUER)
  })

  it("forwards any other IdP error as server_error", async () => {
    const { h, state, cookie } = await begin()
    const response = await handled(
      h.auth,
      callback(`state=${state}&error=temporarily_unavailable`, cookie),
    )

    expect(
      new URL(response.headers.get("location") ?? "").searchParams.get("error"),
    ).toBe("server_error")
  })

  it("shows a page when the IdP exchange fails", async () => {
    const { h, state, cookie } = await begin()
    const code = h.idp.approveLogin()

    h.idp.failExchange = true

    const response = await handled(
      h.auth,
      callback(`state=${state}&code=${code}`, cookie),
    )

    expect(response.status).toBe(400)
    expect(h.events.map((e) => e.type)).toContain("identity_provider_error")
  })

  it("refuses a login without a subject", async () => {
    const { h, state, cookie } = await begin()
    const code = h.idp.approveLogin()

    h.idp.login = { subject: "" }

    const response = await handled(
      h.auth,
      callback(`state=${state}&code=${code}`, cookie),
    )

    expect(response.status).toBe(400)
  })

  it("passes the RFC 9207 iss parameter through to the IdP", async () => {
    const { h, state, cookie } = await begin()
    const code = h.idp.approveLogin()
    let seen: string | undefined

    const original = h.idp.exchangeCode.bind(h.idp)

    h.idp.exchangeCode = async (input) => {
      seen = input.issuer

      return original(input)
    }

    await handled(
      h.auth,
      callback(
        `state=${state}&code=${code}&iss=https://idp.example.net`,
        cookie,
      ),
    )
    expect(seen).toBe("https://idp.example.net")
  })
})

describe("POST /consent", () => {
  it("approval stores a grant with a sealed upstream token and returns code, state and iss", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const response = await handled(h.auth, consentRequest(screen))

    expect(response.status).toBe(303)

    const location = new URL(response.headers.get("location") ?? "")

    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT)
    expect(location.searchParams.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(location.searchParams.get("state")).toBe("client-state-1")
    expect(location.searchParams.get("iss")).toBe(ISSUER)

    const granted = h.events.find((e) => e.type === "consent_approved")

    expect(granted).toMatchObject({ clientId, subject: "person-1" })

    const grantId =
      granted?.type === "consent_approved" ? granted.grantId : "missing"
    const grant = await h.store.getGrant(grantId)

    expect(grant?.sealedUpstreamRefreshToken).toBeDefined()
    expect(grant?.sealedUpstreamRefreshToken).not.toContain("upstream-refresh")
    expect(JSON.stringify(h.events)).not.toContain("upstream-")
  })

  it("denies: redirects with access_denied and creates nothing", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const response = await handled(h.auth, consentRequest(screen, "deny"))
    const location = new URL(response.headers.get("location") ?? "")

    expect(location.searchParams.get("error")).toBe("access_denied")
    expect(location.searchParams.get("state")).toBe("client-state-1")
    expect(location.searchParams.get("iss")).toBe(ISSUER)
    expect(location.searchParams.has("code")).toBe(false)
    expect(h.events.map((e) => e.type)).toContain("consent_declined")
  })

  it("treats a missing decision as deny", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const response = await handled(h.auth, consentRequest(screen, ""))

    expect(
      new URL(response.headers.get("location") ?? "").searchParams.get("error"),
    ).toBe("access_denied")
  })

  it("refuses a wrong CSRF token and burns the request", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const forged = await handled(
      h.auth,
      consentRequest({ ...screen, csrf: "A".repeat(43) }),
    )

    expect(forged.status).toBe(400)
    expect(forged.headers.get("location")).toBeNull()

    const retry = await handled(h.auth, consentRequest(screen))

    expect(retry.status).toBe(400)
  })

  it("refuses a missing or wrong binding cookie", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const name = screen.cookie.split("=")[0] ?? ""
    const response = await handled(
      h.auth,
      consentRequest({ ...screen, cookie: `${name}=wrong` }),
    )

    expect(response.status).toBe(400)
    expect(h.events).toContainEqual({
      type: "flow_binding_mismatch",
      step: "consent",
    })
  })

  it('accepts Origin "null" (sent under Referrer-Policy: no-referrer)', async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const response = await handled(
      h.auth,
      consentRequest(screen, "approve", { Origin: "null" }),
    )

    expect(response.status).toBe(303)
  })

  it("acts on exactly one submission", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const [a, b] = await Promise.all([
      handled(h.auth, consentRequest(screen)),
      handled(h.auth, consentRequest(screen)),
    ])

    const winners = [a, b].filter((r) => r.status === 303)

    expect(winners.length).toBeGreaterThanOrEqual(1)

    // The loser either finds nothing yet (400) or the winner's own answer.
    const locations = new Set(winners.map((r) => r.headers.get("location")))

    expect(locations.size).toBe(1)
    expect([a, b].every((r) => r.status === 303 || r.status === 400)).toBe(true)
    expect(await h.store.listGrantsBySubject?.("person-1")).toHaveLength(1)
  })

  it("refuses a cross-origin Origin, a non-form body, duplicates and expiry", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())

    expect(
      (
        await handled(
          h.auth,
          consentRequest(screen, "approve", { Origin: "https://evil.example" }),
        )
      ).status,
    ).toBe(400)
    expect(
      (
        await handled(
          h.auth,
          consentRequest(screen, "approve", {
            "Content-Type": "application/json",
          }),
        )
      ).status,
    ).toBe(415)

    const duplicated = new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: screen.cookie,
      },
      body: `interaction=${screen.consentId}&interaction=x&form_token=${screen.csrf}`,
    })

    expect((await handled(h.auth, duplicated)).status).toBe(400)

    const missing = new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "choice=approve",
    })

    expect((await handled(h.auth, missing)).status).toBe(400)

    const oversized = new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `x=${"a".repeat(70_000)}`,
    })

    expect((await handled(h.auth, oversized)).status).toBe(400)

    h.clock.advance(901)
    expect((await handled(h.auth, consentRequest(screen))).status).toBe(400)
  })

  it("shows a 429 page when rate limited", async () => {
    const h = setup({
      rateLimit: (_key, scope) => Promise.resolve(scope !== "consent"),
    })
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())

    expect((await handled(h.auth, consentRequest(screen))).status).toBe(429)
  })

  it("uses a custom consent renderer with the documented context", async () => {
    let seen: unknown
    const h = setup({
      renderConsentPage: (context) => {
        seen = context

        return Object.entries(context.hiddenFields)
          .map(([k, v]) => `<input name="${k}" value="${v}">`)
          .join("")
      },
    })
    const clientId = await registeredClientId(h.auth)

    await reachConsent(h, clientId, newVerifier())
    expect(seen).toMatchObject({
      clientId,
      clientKind: "dynamic",
      redirectHost: "client.example.org",
      redirectIsLoopback: false,
      scopes: ["mcp"],
      formAction: "/consent",
      subjectDisplayName: "Pat Example",
    })
  })
})
