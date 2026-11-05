import { describe, expect, it } from "vitest"

import { McpAuthConfigError } from "../../src/index.js"
import { hasExpired } from "../../src/helpers/time.js"
import {
  authorizeParams,
  authorizeUrl,
  bindingCookie,
  connect,
  handled,
  ISSUER,
  mcpRequest,
  newVerifier,
  REDIRECT,
  reachConsent,
  registerClient,
  registeredClientId,
  setup,
  tokenRequest,
} from "../support/harness.js"

async function startFlow(h: ReturnType<typeof setup>, clientId: string) {
  const start = await handled(
    h.auth,
    new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
  )
  const state = h.idp.lastAuthorization?.state ?? ""
  const code = h.idp.approveLogin()

  return handled(
    h.auth,
    new Request(`${ISSUER}/callback?state=${state}&code=${code}`, {
      headers: { Cookie: bindingCookie(start) },
    }),
  )
}

describe("a broken clock fails closed", () => {
  it("treats non-finite expiry or time as expired", () => {
    expect(hasExpired(Number.NaN, 0)).toBe(true)
    expect(hasExpired(10, Number.NaN)).toBe(true)
    expect(hasExpired(Number.POSITIVE_INFINITY, 0)).toBe(true)
    expect(hasExpired(10, 5)).toBe(false)
  })

  it("refuses requests instead of skipping expiry checks", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)

    h.clock.value = Number.NaN

    await expect(
      h.auth.authenticate(mcpRequest(pair.access_token)),
    ).rejects.toThrow("non-finite")

    const refreshed = await handled(
      h.auth,
      tokenRequest({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: pair.refresh_token,
      }),
    )

    expect(refreshed.status).toBe(500)
  })
})

describe("hooks cannot change validated state", () => {
  it("allowRegistration cannot add a redirect URI to the client it approves", async () => {
    const h = setup({
      allowRegistration: ({ metadata }) => {
        expect(() =>
          (metadata.redirect_uris as string[]).push("https://evil.example/cb"),
        ).toThrow(TypeError)

        return true
      },
    })
    const body: unknown = await (await registerClient(h.auth)).json()
    const id =
      typeof body === "object" && body !== null && "client_id" in body
        ? String(body.client_id)
        : ""

    expect((await h.store.getClient(id))?.redirectUris).toEqual([REDIRECT])
  })

  it("authorizeClient cannot widen the scopes that get stored", async () => {
    const h = setup({
      scopes: ["read", "write"],
      authorizeClient: ({ scopes }) => {
        expect(() => (scopes as string[]).push("write")).toThrow(TypeError)

        return true
      },
    })
    const clientId = await registeredClientId(h.auth)

    await handled(
      h.auth,
      new Request(
        authorizeUrl(
          authorizeParams(clientId, newVerifier(), { scope: "read" }),
        ),
      ),
    )

    const pending = await h.store.getPendingAuthorization(
      h.idp.lastAuthorization?.state ?? "",
    )

    expect(pending?.scopes).toEqual(["read"])
  })

  it("a pre-registered client's redirect URIs cannot be changed through a hook", async () => {
    const h = setup({
      clients: [{ clientId: "desk", redirectUris: [REDIRECT] }],
      authorizeClient: ({ client }) => {
        expect(() =>
          (client.redirectUris as string[]).push("https://evil.example/cb"),
        ).toThrow(TypeError)

        return true
      },
    })

    await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams("desk", newVerifier()))),
    )

    const evil = await handled(
      h.auth,
      new Request(
        authorizeUrl(
          authorizeParams("desk", newVerifier(), {
            redirect_uri: "https://evil.example/cb",
          }),
        ),
      ),
    )

    expect(evil.status).toBe(400)
    expect(evil.headers.get("location")).toBeNull()
  })

  it("mapSubject fields are read once, so a getter cannot swap the subject after validation", async () => {
    let reads = 0
    const h = setup({
      mapSubject: () => ({
        get subject() {
          reads += 1

          return reads === 1 ? "checked-subject" : " unchecked"
        },
      }),
    })
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    expect(result).toMatchObject({ ok: true, subject: "checked-subject" })
    expect(reads).toBe(1)
  })
})

describe("subjects and display names are normalised", () => {
  it.each([
    [" padded"],
    ["padded "],
    ["é"], // not NFC
    ["zero​width"],
  ])("refuses subject %j", async (subject) => {
    const h = setup()

    h.idp.login = { subject }

    const response = await startFlow(h, await registeredClientId(h.auth))

    expect(response.status).toBe(403)
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })

  it("drops a display name with hidden characters instead of showing it", async () => {
    const h = setup()

    h.idp.login = { displayName: "Admin‮resu" }

    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )

    expect(screen.html).not.toContain("Admin")
    expect(screen.html).not.toContain("signed in as")
  })
})

describe("consent page robustness", () => {
  it("renders a scope named like an Object.prototype member", async () => {
    const h = setup({ scopes: ["constructor", "toString"] })
    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )

    expect(screen.response.status).toBe(200)
    expect(screen.html).toContain("<code>constructor</code></li>")
  })

  it("a throwing renderer leaves no consent request behind and revokes the upstream token", async () => {
    const h = setup({
      renderConsentPage: () => {
        throw new Error("template missing")
      },
    })
    let stored = 0
    const put = h.store.putConsentRequest.bind(h.store)

    h.store.putConsentRequest = (request) => {
      stored += 1

      return put(request)
    }

    const response = await startFlow(h, await registeredClientId(h.auth))

    expect(response.status).toBe(500)
    expect(stored).toBe(0)
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })
})

describe("configuration bounds", () => {
  it.each([
    [{ paths: { token: "//evil.example/token" } }, "paths.token"],
    [{ paths: { token: "/a//b" } }, "paths.token"],
    [{ paths: { token: "/a\\b" } }, "paths.token"],
    [{ paths: { token: "/a/../token" } }, "paths.token"],
    [{ paths: { token: "/to ken" } }, "paths.token"],
    [
      { paths: { token: "/.well-known/oauth-authorization-server" } },
      "collides",
    ],
    [
      { paths: { token: "/.well-known/oauth-protected-resource/mcp" } },
      "collides",
    ],
    [{ paths: { authorize: "/mcp" } }, "collides"],
    [{ lifetimes: { authorizationCode: 601 } }, "authorizationCode"],
    [{ lifetimes: { pendingAuthorization: 3601 } }, "pendingAuthorization"],
    [{ lifetimes: { accessToken: 86_401 } }, "accessToken"],
    [{ lifetimes: { refreshToken: 34_560_001 } }, "refreshToken"],
    [{ lifetimes: { grant: 34_560_001 } }, "grant"],
  ])("refuses %o", (overrides, message) => {
    expect(() => setup(overrides)).toThrow(McpAuthConfigError)
    expect(() => setup(overrides)).toThrow(message)
  })

  it("accepts the largest allowed lifetimes", () => {
    expect(() =>
      setup({
        lifetimes: {
          authorizationCode: 600,
          pendingAuthorization: 3600,
          accessToken: 86_400,
          refreshToken: 34_560_000,
          grant: 34_560_000,
        },
      }),
    ).not.toThrow()
  })

  it("rateLimit admits only a literal true", async () => {
    for (const verdict of ["yes", 1, {}, undefined]) {
      const h = setup({
        rateLimit: () => Promise.resolve(verdict as unknown as boolean),
      })

      expect((await registerClient(h.auth)).status).toBe(429)
    }
  })
})
