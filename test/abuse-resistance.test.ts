import { beforeEach, describe, expect, it, vi } from "vitest"

const safeFetch = vi.hoisted(() =>
  vi.fn<
    (url: string, init?: RequestInit, options?: object) => Promise<Response>
  >(),
)

vi.mock("@gydr-ai/safe-fetch", () => ({ safeFetch }))

import { GrantInactiveError } from "../src/index.js"
import { hasHiddenCharacters } from "../src/helpers/text.js"
import {
  authorizeParams,
  authorizeUrl,
  bindingCookie,
  connect,
  consentRequest,
  errorOf,
  type Harness,
  handled,
  ISSUER,
  mcpRequest,
  newVerifier,
  obtainCode,
  REDIRECT,
  reachConsent,
  registerClient,
  registeredClientId,
  setup,
  tokenRequest,
} from "./support/harness.js"

beforeEach(() => {
  safeFetch.mockReset()
})

async function clientIdOf(response: Response): Promise<string> {
  const body: unknown = await response.json()

  if (
    typeof body === "object" &&
    body !== null &&
    "client_id" in body &&
    typeof body.client_id === "string"
  ) {
    return body.client_id
  }

  throw new Error("no client_id")
}

function refresh(clientId: string, token: string) {
  return tokenRequest({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: token,
  })
}

async function flood(h: Harness, count: number): Promise<void> {
  for (let i = 0; i < count; i += 1) {
    await registerClient(h.auth, { redirect_uris: [REDIRECT] })
  }
}

describe("dynamic clients in the memory store", () => {
  it("a registration flood never evicts a client with a live grant", async () => {
    const h = setup({}, { maxEntriesPerCollection: 3 })
    const { clientId, pair } = await connect(h)

    await flood(h, 20)

    expect(await h.store.getClient(clientId)).toBeDefined()
    expect(
      (await handled(h.auth, refresh(clientId, pair.refresh_token))).status,
    ).toBe(200)
  })

  it("evicts the least recently used grant-less client first", async () => {
    const h = setup({}, { maxEntriesPerCollection: 2 })
    const a = await registeredClientId(h.auth)
    const b = await registeredClientId(h.auth)

    await h.store.getClient(a) // a is now more recently used than b
    await registeredClientId(h.auth)

    expect(await h.store.getClient(a)).toBeDefined()
    expect(await h.store.getClient(b)).toBeUndefined()
  })

  it("a client whose last grant ends becomes evictable again", async () => {
    const h = setup({}, { maxEntriesPerCollection: 2 })
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!result.ok) throw new Error("expected ok")

    await h.auth.revokeGrant(result.grantId)
    await flood(h, 3)
    expect(await h.store.getClient(result.clientId)).toBeUndefined()
  })

  it("deletes an unused grant-less dynamic client after the idle lifetime", async () => {
    const h = setup({}, { dynamicClientIdleSeconds: 100 })
    const idle = await registeredClientId(h.auth)
    const used = await registeredClientId(h.auth)

    h.clock.advance(60)
    await h.store.getClient(used)
    h.clock.advance(60)

    expect(await h.store.getClient(idle)).toBeUndefined()
    expect(await h.store.getClient(used)).toBeDefined()
  })

  it("keeps a client with a live grant past the idle lifetime, and static clients", async () => {
    const h = setup({}, { dynamicClientIdleSeconds: 100 })
    const { clientId } = await connect(h)

    await h.store.putClient({
      clientId: "static",
      redirectUris: [REDIRECT],
      kind: "static",
      createdAt: 0,
    })
    h.clock.advance(1000)

    expect(await h.store.getClient(clientId)).toBeDefined()
    expect(await h.store.getClient("static")).toBeDefined()
  })

  it("registration of 20,000 clients stays fast (O(1) eviction)", async () => {
    const h = setup({}, { maxEntriesPerCollection: 1000 })
    const started = performance.now()

    for (let i = 0; i < 20_000; i += 1) {
      await h.store.putClient({
        clientId: `c${i}`,
        redirectUris: [],
        kind: "dynamic",
        createdAt: 0,
      })
    }

    expect(performance.now() - started).toBeLessThan(2000)
  })
})

describe("the upstream refresh token is revoked when no grant results", () => {
  it("on deny", async () => {
    const h = setup()
    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )

    await handled(h.auth, consentRequest(screen, "deny"))
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })

  it("when the consent request had expired", async () => {
    const h = setup()
    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )

    h.clock.advance(901)
    expect((await handled(h.auth, consentRequest(screen))).status).toBe(400)
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })

  it("when the submission fails the CSRF or binding check", async () => {
    const h = setup()
    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )

    await handled(h.auth, consentRequest({ ...screen, csrf: "A".repeat(43) }))
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })

  it("when the IdP login has no subject", async () => {
    const h = setup()

    h.idp.login = { subject: "" }
    await expect(
      reachConsent(h, await registeredClientId(h.auth), newVerifier()),
    ).rejects.toThrow()
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })

  it("never on approve", async () => {
    const h = setup()

    await connect(h)
    expect(h.idp.revoked).toEqual([])
  })
})

describe("refreshReuseGraceSeconds: 0", () => {
  it("treats a second use in the same millisecond as reuse", async () => {
    const h = setup({ refreshReuseGraceSeconds: 0 })
    const { clientId, pair } = await connect(h)

    expect(
      (await handled(h.auth, refresh(clientId, pair.refresh_token))).status,
    ).toBe(200)

    const second = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(await errorOf(second)).toBe("invalid_grant")
    expect(h.events.map((e) => e.type)).toContain("refresh_token_replayed")
  })
})

describe("registered grant_types and scope", () => {
  it("a client that did not register refresh_token gets no refresh token", async () => {
    const h = setup()
    const clientId = await clientIdOf(
      await registerClient(h.auth, { redirect_uris: [REDIRECT] }),
    )
    const verifier = newVerifier()
    const code = await obtainCode(h, clientId, verifier)
    const response = await handled(
      h.auth,
      tokenRequest({
        grant_type: "authorization_code",
        client_id: clientId,
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    )
    const body: unknown = await response.json()

    expect(response.status).toBe(200)
    expect(body).toHaveProperty("access_token")
    expect(body).not.toHaveProperty("refresh_token")

    const refused = await handled(h.auth, refresh(clientId, "A".repeat(43)))

    expect(await errorOf(refused)).toBe("unauthorized_client")
  })

  it("registration echoes the default grant type and the registered scope", async () => {
    const h = setup({ scopes: ["read", "write"] })
    const body: unknown = await (
      await registerClient(h.auth, { redirect_uris: [REDIRECT], scope: "read" })
    ).json()

    expect(body).toMatchObject({
      grant_types: ["authorization_code"],
      scope: "read",
    })
  })

  it("requests must stay within a registered scope", async () => {
    const h = setup({ scopes: ["read", "write"] })
    const clientId = await clientIdOf(
      await registerClient(h.auth, {
        redirect_uris: [REDIRECT],
        scope: "read",
        grant_types: ["authorization_code", "refresh_token"],
      }),
    )
    const outside = await handled(
      h.auth,
      new Request(
        authorizeUrl(
          authorizeParams(clientId, newVerifier(), { scope: "write" }),
        ),
      ),
    )

    expect(outside.status).toBe(400)
    expect(outside.headers.get("location")).toBeNull()

    await reachConsent(h, clientId, newVerifier())
    expect(h.events).toContainEqual({
      type: "authorization_started",
      clientId,
      scopes: ["read"],
    })
  })

  it("applies a metadata document's grant_types and scope", async () => {
    const h = setup({ scopes: ["read", "write"] })
    const url = "https://app.example.com/client.json"

    safeFetch.mockResolvedValue(
      Response.json({
        client_id: url,
        redirect_uris: [REDIRECT],
        grant_types: ["authorization_code"],
        scope: "read unknown",
      }),
    )

    const verifier = newVerifier()
    const code = await obtainCode(h, url, verifier)
    const response = await handled(
      h.auth,
      tokenRequest({
        grant_type: "authorization_code",
        client_id: url,
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    )
    const body: unknown = await response.json()

    expect(body).toMatchObject({ scope: "read" })
    expect(body).not.toHaveProperty("refresh_token")
  })

  it("rejects a metadata document with no supported scope", async () => {
    const h = setup()

    safeFetch.mockResolvedValue(
      Response.json({
        client_id: "https://app.example.com/client.json",
        redirect_uris: [REDIRECT],
        scope: "admin",
      }),
    )

    const response = await handled(
      h.auth,
      new Request(
        authorizeUrl(
          authorizeParams("https://app.example.com/client.json", newVerifier()),
        ),
      ),
    )

    expect(response.status).toBe(400)
    expect(h.events).toContainEqual(
      expect.objectContaining({ reason: "scope_unusable" }),
    )
  })

  it("never refreshes under a grant that does not allow it", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!result.ok) throw new Error("expected ok")

    const grant = await h.store.getGrant(result.grantId)

    if (grant === undefined) throw new Error("no grant")

    await h.store.putGrant({ ...grant, allowRefresh: false })
    expect(
      await errorOf(
        await handled(h.auth, refresh(clientId, pair.refresh_token)),
      ),
    ).toBe("invalid_grant")
  })
})

describe("callback browser binding", () => {
  it("a callback without the cookie leaves the flow open", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const start = await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    )
    const cookie = bindingCookie(start)
    const state = h.idp.lastAuthorization?.state ?? ""
    const code = h.idp.approveLogin()
    const withoutCookie = await handled(
      h.auth,
      new Request(`${ISSUER}/callback?state=${state}&code=bogus`),
    )

    expect(withoutCookie.status).toBe(400)

    const withCookie = await handled(
      h.auth,
      new Request(`${ISSUER}/callback?state=${state}&code=${code}`, {
        headers: { Cookie: cookie },
      }),
    )

    expect(withCookie.status).toBe(200)
  })

  it("only one of two callbacks with the cookie proceeds", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const start = await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    )
    const cookie = bindingCookie(start)
    const state = h.idp.lastAuthorization?.state ?? ""
    const code = h.idp.approveLogin()
    const call = () =>
      handled(
        h.auth,
        new Request(`${ISSUER}/callback?state=${state}&code=${code}`, {
          headers: { Cookie: cookie },
        }),
      )
    const statuses = (await Promise.all([call(), call()])).map((r) => r.status)

    expect(statuses.sort()).toEqual([200, 400])
  })
})

describe("client names with hidden characters", () => {
  it.each([
    0x00ad, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202e, 0x2060,
    0x2064, 0x2066, 0x2069, 0xfeff, 0x2028, 0x2029, 0x061c, 0xe000, 0x0085,
  ])("refuses U+%s", async (code) => {
    const name = `Good${String.fromCodePoint(code)}App`

    expect(hasHiddenCharacters(name)).toBe(true)

    const h = setup()
    const response = await registerClient(h.auth, {
      redirect_uris: [REDIRECT],
      client_name: name,
    })

    expect(response.status).toBe(400)
  })

  it("accepts ordinary international names", () => {
    expect(hasHiddenCharacters("Café Agent 東京 ✓")).toBe(false)
  })
})

describe("metadata-document fetch limits", () => {
  const url = "https://slow.example.com/client.json"
  const authorize = (h: Harness) =>
    handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(url, newVerifier()))),
    )

  it("waits before contacting a failed URL again", async () => {
    const h = setup()

    safeFetch.mockRejectedValue(
      Object.assign(new Error("slow"), { code: "timeout" }),
    )
    await authorize(h)
    await authorize(h)
    expect(safeFetch).toHaveBeenCalledTimes(1)

    h.clock.advance(61)
    await authorize(h)
    expect(safeFetch).toHaveBeenCalledTimes(2)
  })

  it("shares one fetch between concurrent requests", async () => {
    const h = setup()

    safeFetch.mockImplementation(
      () =>
        new Promise((_, reject) =>
          setTimeout(() => {
            reject(new Error("slow"))
          }, 20),
        ),
    )
    await Promise.all([authorize(h), authorize(h), authorize(h)])
    expect(safeFetch).toHaveBeenCalledTimes(1)
  })
})

describe("revocation during an upstream renewal", () => {
  it("revokes the freshly rotated upstream refresh token", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!result.ok) throw new Error("expected ok")

    h.idp.refreshDelayMs = 20
    h.clock.advance(3550)

    const refreshing = result.getUpstreamAccessToken()

    await new Promise((resolve) => setTimeout(resolve, 5))
    await h.auth.revokeGrant(result.grantId)

    await expect(refreshing).rejects.toBeInstanceOf(GrantInactiveError)
    expect(h.idp.revoked).toEqual(["upstream-refresh-0", "upstream-refresh-1"])
  })
})
