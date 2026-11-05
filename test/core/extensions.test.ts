import { describe, expect, it, vi } from "vitest"

const safeFetch = vi.hoisted(() =>
  vi.fn<
    (url: string, init?: RequestInit, options?: object) => Promise<Response>
  >(),
)

vi.mock("@gydr-ai/safe-fetch", () => ({ safeFetch }))

import { McpAuthConfigError, type StaticClient } from "../../src/index.js"
import {
  authorizeParams,
  authorizeUrl,
  bindingCookie,
  challengeOf,
  connect,
  consentRequest,
  errorOf,
  handled,
  ISSUER,
  mcpRequest,
  newVerifier,
  obtainCode,
  REDIRECT,
  reachConsent,
  readPair,
  registerClient,
  registeredClientId,
  setup,
  tokenRequest,
} from "../support/harness.js"

const STATIC: StaticClient = {
  clientId: "desktop-app",
  clientName: "Desktop App",
  redirectUris: [REDIRECT],
}

/** The status of an error page, which is never a redirect. */
function pageStatus(response: Response): number {
  if (response.headers.get("location") !== null) {
    throw new Error("an error page was expected, not a redirect")
  }

  return response.status
}

async function start(
  h: ReturnType<typeof setup>,
  clientId: string,
  extra = {},
) {
  return handled(
    h.auth,
    new Request(authorizeUrl(authorizeParams(clientId, newVerifier(), extra))),
  )
}

describe("clients option (pre-registered clients)", () => {
  it("serves a listed client without registration and labels it as operator-added", async () => {
    const h = setup({ clients: [STATIC] })
    const screen = await reachConsent(h, "desktop-app", newVerifier())

    expect(screen.html).toContain("The operator of this service added")
  })

  it("takes precedence over a store record with the same id", async () => {
    const h = setup({ clients: [STATIC] })

    await h.store.putClient({
      clientId: "desktop-app",
      redirectUris: ["https://evil.example/cb"],
      kind: "dynamic",
      createdAt: 0,
    })

    const response = await start(h, "desktop-app", {
      redirect_uri: "https://evil.example/cb",
    })

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
  })

  it("issues no refresh token when the client lists only authorization_code", async () => {
    const h = setup({
      clients: [{ ...STATIC, grantTypes: ["authorization_code"] }],
    })
    const verifier = newVerifier()
    const code = await obtainCode(h, "desktop-app", verifier)
    const body: unknown = await (
      await handled(
        h.auth,
        tokenRequest({
          grant_type: "authorization_code",
          client_id: "desktop-app",
          code,
          redirect_uri: REDIRECT,
          code_verifier: verifier,
        }),
      )
    ).json()

    expect(body).not.toHaveProperty("refresh_token")
  })

  it.each([
    [
      { ...STATIC, redirectUris: ["http://client.example.org/cb"] },
      "redirect URI refused",
    ],
    [
      { ...STATIC, redirectUris: ["https://a.example/cb#x"] },
      "redirect URI refused",
    ],
    [{ ...STATIC, redirectUris: [] }, "redirectUris"],
    [{ ...STATIC, clientId: "https://app.example.com/c.json" }, "https URL"],
    [{ ...STATIC, clientId: "HTTPS://app.example.com/c.json" }, "https URL"],
    [{ ...STATIC, clientId: " " }, "visible characters"],
    [{ ...STATIC, clientName: "Bad‮Name" }, "display name"],
    [{ ...STATIC, scopes: ["admin"] }, "subset"],
    [{ ...STATIC, scopes: [] }, "must not be empty"],
    [
      { ...STATIC, grantTypes: ["refresh_token"] as const },
      "authorization_code",
    ],
  ] satisfies [StaticClient, string][])(
    "refuses %o at start-up (same rules as registration)",
    (client, message) => {
      expect(() => setup({ clients: [client] })).toThrow(McpAuthConfigError)
      expect(() => setup({ clients: [client] })).toThrow(message)
    },
  )

  it("refuses a client listed twice", () => {
    expect(() => setup({ clients: [STATIC, STATIC] })).toThrow("twice")
  })
})

describe("scopeDescriptions option", () => {
  it("shows escaped descriptions on the consent screen", async () => {
    const h = setup({
      scopeDescriptions: { mcp: "Read <b>your</b> files" },
    })
    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )

    expect(screen.html).toContain("Read &lt;b&gt;your&lt;/b&gt; files")
    expect(screen.html).not.toContain("<b>your</b>")
  })

  it.each([
    [{ unknown: "x" }, "not in scopes"],
    [{ mcp: "" }, "visible characters"],
    [{ mcp: "a​b" }, "visible characters"],
  ])("refuses %o", (scopeDescriptions, message) => {
    expect(() => setup({ scopeDescriptions })).toThrow(message)
  })
})

describe("authorizeClient hook (may only refuse)", () => {
  it("receives the verified request and can refuse with access_denied", async () => {
    const seen: unknown[] = []
    const h = setup({
      authorizeClient: (context) => {
        seen.push({
          clientId: context.client.clientId,
          redirectUri: context.redirectUri,
          scopes: context.scopes,
        })

        return false
      },
    })
    const clientId = await registeredClientId(h.auth)
    const response = await start(h, clientId)

    expect(pageStatus(response)).toBe(403)
    expect(seen).toEqual([{ clientId, redirectUri: REDIRECT, scopes: ["mcp"] }])
  })

  it("refuses when the hook throws or returns a non-boolean", async () => {
    for (const authorizeClient of [
      () => {
        throw new Error("policy down")
      },
      // A sloppy hook returning a truthy non-boolean is not consent.
      () => "yes" as unknown as boolean,
    ]) {
      const h = setup({ authorizeClient })
      const response = await start(h, await registeredClientId(h.auth))

      expect(pageStatus(response)).toBe(403)
    }
  })

  it("cannot relax protocol checks: an allow-all hook still sees PKCE, resource and redirect refusals", async () => {
    const hook = vi.fn(() => true)
    const h = setup({ authorizeClient: hook })
    const clientId = await registeredClientId(h.auth)

    expect(
      pageStatus(await start(h, clientId, { code_challenge_method: "plain" })),
    ).toBe(400)
    expect(
      pageStatus(
        await start(h, clientId, { resource: "https://x.example/mcp" }),
      ),
    ).toBe(400)
    expect(
      (await start(h, clientId, { redirect_uri: "https://evil.example/cb" }))
        .status,
    ).toBe(400)
    expect(hook).not.toHaveBeenCalled()
  })

  it("cannot skip consent: an allow-all hook still leads to the consent screen", async () => {
    const h = setup({ authorizeClient: () => true })
    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )

    expect(screen.html).toContain("Connect")
    expect(screen.csrf).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })
})

describe("allowRegistration hook (may only refuse)", () => {
  it("can refuse a registration with 403 and stores nothing", async () => {
    const h = setup({
      allowRegistration: ({ metadata }) => metadata.client_name === "Trusted",
    })
    const refused = await registerClient(h.auth, {
      redirect_uris: [REDIRECT],
      client_name: "Other",
    })

    expect(refused.status).toBe(403)
    expect(await errorOf(refused)).toBe("invalid_client_metadata")
    expect(
      (
        await registerClient(h.auth, {
          redirect_uris: [REDIRECT],
          client_name: "Trusted",
        })
      ).status,
    ).toBe(201)
  })

  it("refuses when the hook throws", async () => {
    const h = setup({
      allowRegistration: () => {
        throw new Error("down")
      },
    })

    expect((await registerClient(h.auth)).status).toBe(403)
  })

  it("cannot admit invalid metadata: an allow-all hook is not even asked", async () => {
    const hook = vi.fn(() => true)
    const h = setup({ allowRegistration: hook })
    const response = await registerClient(h.auth, {
      redirect_uris: ["http://client.example.org/cb"],
    })

    expect(await errorOf(response)).toBe("invalid_redirect_uri")
    expect(hook).not.toHaveBeenCalled()
  })
})

describe("mapSubject hook (enrichment)", () => {
  it("replaces the subject and display name stored on the grant", async () => {
    const h = setup({
      mapSubject: ({ subject, claims }) => ({
        subject: `idp|${subject}`,
        displayName: claims.email_verified === true ? "Verified Pat" : "Pat",
      }),
    })
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    expect(result).toMatchObject({ ok: true, subject: "idp|person-1" })
  })

  it.each([
    ["an empty subject", () => ({ subject: "" })],
    [
      "a non-string subject",
      () => ({ subject: 42 }) as unknown as { subject: string },
    ],
    ["an over-long subject", () => ({ subject: "x".repeat(513) })],
    [
      "a throwing hook",
      () => {
        throw new Error("down")
      },
    ],
  ])(
    "stops sign-in on %s and revokes the upstream token",
    async (_name, mapSubject) => {
      const h = setup({ mapSubject })
      const clientId = await registeredClientId(h.auth)

      await expect(reachConsent(h, clientId, newVerifier())).rejects.toThrow()
      expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
      expect(h.events).toContainEqual(
        expect.objectContaining({ reason: "subject_not_permitted" }),
      )
    },
  )
})

describe("allowSubject hook (may only refuse)", () => {
  it("receives the claims and the client, and a refusal shows 403 and revokes upstream", async () => {
    let seen: unknown
    const h = setup({
      allowSubject: (context) => {
        seen = context

        return false
      },
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
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
    expect(seen).toMatchObject({
      subject: "person-1",
      claims: { email_verified: true },
      client: { clientId, kind: "dynamic" },
    })
  })

  it("cannot bypass the browser binding: an allow-all hook is not reached without the cookie", async () => {
    const hook = vi.fn(() => true)
    const h = setup({ allowSubject: hook })
    const clientId = await registeredClientId(h.auth)

    await handled(
      h.auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    )

    const state = h.idp.lastAuthorization?.state ?? ""
    const code = h.idp.approveLogin()
    const response = await handled(
      h.auth,
      new Request(`${ISSUER}/callback?state=${state}&code=${code}`),
    )

    expect(response.status).toBe(400)
    expect(hook).not.toHaveBeenCalled()
  })

  it("cannot bypass CSRF on consent", async () => {
    const h = setup({ allowSubject: () => true })
    const screen = await reachConsent(
      h,
      await registeredClientId(h.auth),
      newVerifier(),
    )
    const response = await handled(
      h.auth,
      consentRequest({ ...screen, csrf: "A".repeat(43) }),
    )

    expect(response.status).toBe(400)
  })
})

describe("allowClientMetadataUrl hook (may only refuse)", () => {
  const url = "https://app.example.com/client.json"

  it("refuses before anything is downloaded", async () => {
    const h = setup({ allowClientMetadataUrl: () => false })

    safeFetch.mockReset()
    expect((await start(h, url)).status).toBe(400)
    expect(safeFetch).not.toHaveBeenCalled()
    expect(h.events).toContainEqual(
      expect.objectContaining({ reason: "not_allowed_by_policy" }),
    )
  })

  it("refuses when the hook throws", async () => {
    const h = setup({
      allowClientMetadataUrl: () => Promise.reject(new Error("down")),
    })

    safeFetch.mockReset()
    expect((await start(h, url)).status).toBe(400)
    expect(safeFetch).not.toHaveBeenCalled()
  })

  it("cannot relax document checks: an allow-all hook still refuses a mismatched client_id", async () => {
    const h = setup({ allowClientMetadataUrl: () => true })

    safeFetch.mockReset()
    safeFetch.mockResolvedValue(
      Response.json({
        client_id: "https://evil.example/c.json",
        redirect_uris: [REDIRECT],
      }),
    )
    expect((await start(h, url)).status).toBe(400)
  })
})

describe("getGrantContext hook (enrichment)", () => {
  it("exposes a JSON copy on AuthResult.context", async () => {
    const shared = { tenant: "acme", roles: ["reader"] }
    const h = setup({
      getGrantContext: (grant) => ({ ...shared, subject: grant.subject }),
    })
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!result.ok) throw new Error("expected ok")

    expect(result.context).toEqual({
      tenant: "acme",
      roles: ["reader"],
      subject: "person-1",
    })

    shared.roles.push("admin")
    expect(result.context).toEqual({
      tenant: "acme",
      roles: ["reader"],
      subject: "person-1",
    })
  })

  it("is undefined without the hook or when the hook returns undefined", async () => {
    for (const h of [setup(), setup({ getGrantContext: () => undefined })]) {
      const { pair } = await connect(h)
      const result = await h.auth.authenticate(mcpRequest(pair.access_token))

      expect(result).toMatchObject({ ok: true, context: undefined })
    }
  })

  it("cannot change who the token belongs to or what it may access", async () => {
    const h = setup({
      getGrantContext: (grant) => {
        // The input is a frozen copy: tampering throws and changes nothing.
        expect(() => (grant.scopes as string[]).push("admin")).toThrow(
          TypeError,
        )

        return { subject: "someone-else" }
      },
    })
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    expect(result).toMatchObject({
      ok: true,
      subject: "person-1",
      scopes: ["mcp"],
      context: { subject: "someone-else" },
    })
  })

  it("answers a generic 500 for oversized, unserializable or throwing hooks, without the error text", async () => {
    for (const getGrantContext of [
      () => ({ blob: "x".repeat(5000) }),
      () => ({ big: 1n }),
      () => {
        throw new Error("db password is hunter2")
      },
    ]) {
      const h = setup({ getGrantContext })
      const { pair } = await connect(h)
      const result = await h.auth.authenticate(mcpRequest(pair.access_token))

      if (result.ok) throw new Error("expected failure")

      expect(result.response.status).toBe(500)
      expect(await result.response.text()).not.toContain("hunter2")
      expect(JSON.stringify(h.events)).not.toContain("hunter2")
      expect(h.events.map((e) => e.type)).toContain("grant_context_failed")
    }
  })

  it("honours limits.grantContextBytes", async () => {
    const h = setup({
      getGrantContext: () => ({ blob: "x".repeat(5000) }),
      limits: { grantContextBytes: 10_000 },
    })
    const { pair } = await connect(h)

    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      true,
    )
  })
})

describe("extensions never weaken token rules", () => {
  it("refresh rotation and replay detection apply with every hook installed", async () => {
    const h = setup({
      authorizeClient: () => true,
      allowRegistration: () => true,
      allowSubject: () => true,
      mapSubject: ({ subject }) => ({ subject }),
      getGrantContext: () => ({}),
    })
    const { clientId, pair } = await connect(h)
    const refresh = () =>
      handled(
        h.auth,
        tokenRequest({
          grant_type: "refresh_token",
          client_id: clientId,
          refresh_token: pair.refresh_token,
        }),
      )

    await readPair(await refresh())
    h.clock.advance(11)
    expect(await errorOf(await refresh())).toBe("invalid_grant")
    expect(h.events.map((e) => e.type)).toContain("refresh_token_replayed")
    expect(challengeOf("x")).toBeTypeOf("string")
  })
})
