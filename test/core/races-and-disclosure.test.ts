import { randomBytes } from "node:crypto"

import { describe, expect, it } from "vitest"

import { isIssuerUrl } from "../../src/core/clients.js"
import { defaultConsentPage } from "../../src/core/pages.js"
import { isRecord } from "../../src/helpers/guards.js"
import {
  createAesGcmSealer,
  createMemoryStore,
  GrantInactiveError,
  type ConsentPageContext,
  type McpAuthEvent,
  type OAuthStore,
} from "../../src/index.js"
import {
  connect,
  consentRequest,
  handled,
  mcpRequest,
  newVerifier,
  obtainCode,
  reachConsent,
  registeredClientId,
  setup,
  tokenRequest,
} from "../support/harness.js"

const sleep = (ms: number) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms)
  })

async function liveGrant(h: ReturnType<typeof setup>): Promise<string> {
  const { pair } = await connect(h)
  const result = await h.auth.authenticate(mcpRequest(pair.access_token))

  if (!result.ok) throw new Error("expected ok")

  return result.grantId
}

describe("revocation racing an upstream renewal", () => {
  it("revokes the refresh token a renewal stored while the grant_revoked event ran", async () => {
    let slow = false
    const h = setup({
      onEvent: async (event) => {
        if (slow && event.type === "grant_revoked") await sleep(60)
      },
    })
    const grantId = await liveGrant(h)

    h.idp.refreshDelayMs = 10
    slow = true

    const renewal = h.auth.renewUpstream(grantId).catch(() => "failed")

    await sleep(2)
    await h.auth.revokeGrant(grantId)
    await renewal

    // The rotated token is the one the identity provider must forget.
    expect(h.idp.revoked).toContain("upstream-refresh-1")
  })

  it("a renewal that finishes after the grant is gone revokes its own new token", async () => {
    const h = setup()
    const grantId = await liveGrant(h)

    h.idp.refreshDelayMs = 30

    const renewal = h.auth.renewUpstream(grantId)

    await sleep(2)
    await h.auth.revokeGrant(grantId)
    await expect(renewal).rejects.toThrow()
    expect(h.idp.revoked).toEqual(["upstream-refresh-0", "upstream-refresh-1"])
  })

  it("does not rely on updateGrant noticing the delete", async () => {
    const base = setup()
    // A store whose updateGrant reports success even for a deleted grant.
    const store: OAuthStore = {
      ...base.store,
      updateGrant: async (id, update) => {
        await base.store.updateGrant(id, update)

        return true
      },
    }
    const h = setup({ store })
    const grantId = await liveGrant(h)

    h.idp.refreshDelayMs = 30

    const renewal = h.auth.renewUpstream(grantId)

    await sleep(2)
    await h.auth.revokeGrant(grantId)
    await expect(renewal).rejects.toThrow(GrantInactiveError)
    expect(h.idp.revoked).toContain("upstream-refresh-1")
  })

  it("the memory store's deleteGrant returns the deleted record", async () => {
    const store = createMemoryStore()

    await store.putGrant({
      grantId: "g",
      clientId: "c",
      subject: "s",
      scopes: ["mcp"],
      resource: "https://mcp.example.com/mcp",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      sealedUpstreamRefreshToken: "sealed-latest",
    })
    expect(await store.deleteGrant("g")).toMatchObject({
      grantId: "g",
      sealedUpstreamRefreshToken: "sealed-latest",
    })
    expect(await store.deleteGrant("g")).toBeUndefined()
  })

  it("prefers the record deleteGrant returns over the one read before", async () => {
    const base = setup()
    const sealer = createAesGcmSealer({
      keys: { k1: randomBytes(32) },
      currentKid: "k1",
    })
    const store: OAuthStore = {
      ...base.store,
      // Simulates a renewal that stored a new token between the server's
      // last read and the delete: only the deleted row knows it.
      deleteGrant: async (id) => {
        const removed = await base.store.deleteGrant(id)

        return isRecord(removed)
          ? {
              ...removed,
              sealedUpstreamRefreshToken: await sealer.seal(
                "upstream-refresh-9",
                id,
              ),
            }
          : removed
      },
    }
    const h = setup({ store, sealer })

    await h.auth.revokeGrant(await liveGrant(h))
    expect(h.idp.revoked).toEqual(["upstream-refresh-9"])
  })

  it("ignores a deleteGrant result for another grant", async () => {
    const base = setup()
    const store: OAuthStore = {
      ...base.store,
      deleteGrant: async (id) => {
        await base.store.deleteGrant(id)

        return { grantId: "someone-else", sealedUpstreamRefreshToken: "x" }
      },
    }
    const h = setup({ store })

    await h.auth.revokeGrant(await liveGrant(h))
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })

  it("still revokes with a store whose deleteGrant returns nothing", async () => {
    const base = setup()
    const store: OAuthStore = {
      ...base.store,
      deleteGrant: async (id) => {
        await base.store.deleteGrant(id)
      },
    }
    const h = setup({ store })

    await h.auth.revokeGrant(await liveGrant(h))
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })
})

describe("consent replay window", () => {
  it("is enforced even by a store that keeps outcomes forever", async () => {
    const kept = new Map<string, string>()
    const base = setup()
    const store: OAuthStore = {
      ...base.store,
      putConsentOutcome: (key, value) => {
        kept.set(key, value)

        return Promise.resolve()
      },
      getConsentOutcome: (key) => Promise.resolve(kept.get(key)),
    }
    const h = setup({ store })
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const first = await handled(h.auth, consentRequest(screen))
    const soon = await handled(h.auth, consentRequest(screen))

    expect(soon.headers.get("location")).toBe(first.headers.get("location"))

    h.clock.advance(11)

    const late = await handled(h.auth, consentRequest(screen))

    expect(late.status).toBe(400)
    expect(late.headers.get("location")).toBeNull()
  })
})

describe("token endpoint answers", () => {
  it("say nothing about which check a code failed; the event does", async () => {
    const events: McpAuthEvent[] = []
    const h = setup({
      onEvent: (event) => {
        events.push(event)
      },
    })
    const clientId = await registeredClientId(h.auth)
    const verifier = newVerifier()
    const code = await obtainCode(h, clientId, verifier)
    const other = await registeredClientId(h.auth)
    const attempts = [
      { client_id: clientId, code: "A".repeat(43), code_verifier: verifier },
      { client_id: other, code, code_verifier: verifier },
      { client_id: clientId, code, code_verifier: newVerifier() },
      {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: "https://client.example.org/other",
      },
    ]
    const bodies: string[] = []

    for (const params of attempts) {
      const response = await handled(
        h.auth,
        tokenRequest({ grant_type: "authorization_code", ...params }),
      )

      bodies.push(await response.text())
    }

    expect(new Set(bodies).size).toBe(1)
    expect(
      events.flatMap((e) =>
        e.type === "token_request_refused" ? [e.reason] : [],
      ),
    ).toEqual([
      "code_unknown",
      "client_id_mismatch",
      "code_verifier_mismatch",
      "redirect_uri_mismatch",
    ])
  })
})

describe("issuer-equal client ids", () => {
  it.each([
    ["https://auth.example.com", true],
    ["https://auth.example.com/", true],
    ["https://AUTH.example.com", true],
    ["https://auth.example.com:443/", true],
    ["https://auth.example.com./", true],
    ["https://auth.example.com/?", true],
    ["https://auth.example.com/%2e", true],
    ["https://auth.example.com/client.json", false],
    ["https://auth.example.com:8443/", false],
    ["http://auth.example.com/", false],
    ["https://other.example.com/", false],
  ])("%s is the issuer: %s", (url, same) => {
    expect(isIssuerUrl(url, "https://auth.example.com")).toBe(same)
  })
})

describe("default consent page with field errors", () => {
  const base: ConsentPageContext = {
    clientId: "client-1",
    clientKind: "static",
    redirectUri: "https://client.example.org/callback",
    redirectHost: "client.example.org",
    redirectIsLoopback: false,
    scopes: ["mcp"],
    scopeDescriptions: {},
    resource: "https://mcp.example.com/mcp",
    formAction: "/consent",
    hiddenFields: { interaction: "i", form_token: "t" },
    decisionField: "choice",
    locales: [],
  }

  it("shows each message and the submitted value again, escaped", () => {
    const html = defaultConsentPage({
      ...base,
      fieldErrors: { "<org>": '<img src=x onerror="a()">' },
      submitted: { "<org>": '"><script>b()</script>', note: "kept" },
    })

    expect(html).not.toContain("<script>")
    expect(html).not.toContain("<img")
    expect(html).toContain("&lt;img src=x onerror=&quot;a()&quot;&gt;")
    expect(html).toContain('value="&quot;&gt;&lt;script&gt;b()&lt;/script&gt;"')
    expect(html).toContain('name="&lt;org&gt;"')
    expect(html).toContain('name="note" value="kept"')
    expect(html).toContain('aria-invalid="true"')
  })

  it("adds nothing on a first showing", () => {
    expect(defaultConsentPage(base)).not.toContain('type="text"')
  })

  it("renders through the server after readConsentFields asks for a correction", async () => {
    const h = setup({
      readConsentFields: ({ form }) =>
        form.org === "ok"
          ? { ok: true }
          : { ok: false, fieldErrors: { org: "Pick a <real> org" } },
    })
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const response = await handled(
      h.auth,
      consentRequest(screen, "approve", {}, { org: "<b>x</b>" }),
    )
    const html = await response.text()

    expect(response.status).toBe(400)
    expect(html).toContain("Pick a &lt;real&gt; org")
    expect(html).toContain('value="&lt;b&gt;x&lt;/b&gt;"')
    expect(html).not.toContain("<b>x</b>")
  })
})
