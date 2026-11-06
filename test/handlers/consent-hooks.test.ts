import { describe, expect, it, vi } from "vitest"

import { defaultConsentPage } from "../../src/core/pages.js"
import type {
  ConsentPageContext,
  McpAuthOptions,
  ReadConsentFieldsInput,
} from "../../src/index.js"
import {
  consentRequest,
  handled,
  ISSUER,
  mcpRequest,
  newVerifier,
  pageSpy,
  REDIRECT,
  readPair,
  reachConsent,
  registeredClientId,
  RESOURCE,
  setup,
  tokenRequest,
} from "../support/harness.js"

/** A consent renderer that records every context it is given. */
function consentSpy(): {
  seen: ConsentPageContext[]
  renderConsentPage: (context: ConsentPageContext) => string
} {
  const seen: ConsentPageContext[] = []

  return {
    seen,
    renderConsentPage: (context) => {
      seen.push(context)

      return defaultConsentPage(context)
    },
  }
}

async function screenFor(overrides: Partial<McpAuthOptions> = {}) {
  const h = setup(overrides)
  const clientId = await registeredClientId(h.auth)
  const verifier = newVerifier()
  const screen = await reachConsent(h, clientId, verifier)

  return { h, clientId, verifier, screen }
}

function locationOf(response: Response): URL {
  return new URL(response.headers.get("location") ?? "about:blank")
}

describe("consent answer", () => {
  it("is a 303 redirect (OAuth 2.1 § 7.5.4)", async () => {
    const { h, screen } = await screenFor()
    const response = await handled(h.auth, consentRequest(screen))

    expect(response.status).toBe(303)
    expect(locationOf(response).searchParams.get("code")).not.toBeNull()
  })

  it("answers a repeated submission from the same browser with the same redirect", async () => {
    const { h, screen } = await screenFor()
    const first = await handled(h.auth, consentRequest(screen))
    const again = await handled(h.auth, consentRequest(screen))

    expect(again.status).toBe(303)
    expect(again.headers.get("location")).toBe(first.headers.get("location"))
    expect(await h.store.listGrantsBySubject?.("person-1")).toHaveLength(1)
  })

  it("does not answer a repeat from another browser, after the window, or when disabled", async () => {
    const other = await screenFor()

    await handled(other.h.auth, consentRequest(other.screen))

    const foreign = await handled(
      other.h.auth,
      consentRequest({ ...other.screen, cookie: `${other.screen.cookie}x` }),
    )

    expect(foreign.status).toBe(400)

    const late = await screenFor()

    await handled(late.h.auth, consentRequest(late.screen))
    late.h.clock.advance(11)
    expect(
      (await handled(late.h.auth, consentRequest(late.screen))).status,
    ).toBe(400)

    const off = await screenFor({ consentReplaySeconds: 0 })

    await handled(off.h.auth, consentRequest(off.screen))
    expect((await handled(off.h.auth, consentRequest(off.screen))).status).toBe(
      400,
    )
  })

  it("keeps today's behaviour with a store that cannot remember answers", async () => {
    const h = setup()
    const rest = { ...h.store }

    delete rest.putConsentOutcome
    delete rest.getConsentOutcome

    const plain = setup({ store: rest })
    const clientId = await registeredClientId(plain.auth)
    const screen = await reachConsent(plain, clientId, newVerifier())

    expect((await handled(plain.auth, consentRequest(screen))).status).toBe(303)
    expect((await handled(plain.auth, consentRequest(screen))).status).toBe(400)
  })

  it("never puts an authorization code in the store in plain text", async () => {
    const h = setup()
    const saved: string[] = []
    const put = h.store.putConsentOutcome?.bind(h.store)
    const store = {
      ...h.store,
      putConsentOutcome: async (key: string, value: string, at: number) => {
        saved.push(value)
        await put?.(key, value, at)
      },
    }
    const wrapped = setup({ store })
    const clientId = await registeredClientId(wrapped.auth)
    const screen = await reachConsent(wrapped, clientId, newVerifier())
    const response = await handled(wrapped.auth, consentRequest(screen))
    const code = locationOf(response).searchParams.get("code") ?? ""

    // The "being decided" mark, then the answer: both sealed.
    expect(saved).toHaveLength(2)

    for (const value of saved) {
      expect(value).not.toContain(code)
      expect(value).not.toContain("client.example.org")
      expect(value).not.toContain("pending")
    }
  })

  it("refuses a consentReplaySeconds outside 0–60", () => {
    expect(() => setup({ consentReplaySeconds: 61 })).toThrow()
    expect(() => setup({ consentReplaySeconds: -1 })).toThrow()
  })
})

describe("getConsentDetails and readConsentFields", () => {
  it("passes details to the page and fields to the hook, never the package's own fields", async () => {
    const consent = consentSpy()
    const seen: ReadConsentFieldsInput[] = []
    const { h, screen } = await screenFor({
      renderConsentPage: consent.renderConsentPage,
      getConsentDetails: ({ subject, scopes }) => ({
        workspaces: ["alpha", "beta"],
        subject,
        scopes,
      }),
      readConsentFields: (input) => {
        seen.push(input)

        return { ok: true, grantData: { workspace: input.form.workspace } }
      },
      getGrantContext: ({ data }) => ({ data }),
    })

    expect(consent.seen[0]?.details).toEqual({
      workspaces: ["alpha", "beta"],
      subject: "person-1",
      scopes: ["mcp"],
    })

    const response = await handled(
      h.auth,
      consentRequest(screen, "approve", {}, { workspace: "beta" }),
    )

    expect(response.status).toBe(303)
    expect(seen).toHaveLength(1)
    expect(seen[0]?.form).toEqual({ workspace: "beta" })
    expect(Object.isFrozen(seen[0])).toBe(true)
    expect(seen[0]?.details).toEqual(consent.seen[0]?.details)
  })

  it("stores grantData on the grant and exposes it to getGrantContext", async () => {
    const h = setup({
      readConsentFields: ({ form }) => ({
        ok: true,
        grantData: { workspace: form.workspace },
      }),
      getGrantContext: ({ data }) => ({ fromGrant: data }),
    })
    const clientId = await registeredClientId(h.auth)
    const verifier = newVerifier()
    const screen = await reachConsent(h, clientId, verifier)
    const response = await handled(
      h.auth,
      consentRequest(screen, "approve", {}, { workspace: "alpha" }),
    )
    const code = locationOf(response).searchParams.get("code") ?? ""
    const pair = await readPair(
      await handled(
        h.auth,
        tokenRequest({
          grant_type: "authorization_code",
          client_id: clientId,
          code,
          code_verifier: verifier,
          resource: RESOURCE,
        }),
      ),
    )
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!result.ok) throw new Error("expected ok")

    expect(result.context).toEqual({ fromGrant: { workspace: "alpha" } })
    expect((await h.store.getGrant(result.grantId))?.data).toEqual({
      workspace: "alpha",
    })
  })

  it("shows the page again on fieldErrors without using the request up", async () => {
    const consent = consentSpy()
    const { h, screen } = await screenFor({
      renderConsentPage: consent.renderConsentPage,
      readConsentFields: ({ form }) =>
        form.workspace === "alpha"
          ? { ok: true }
          : { ok: false, fieldErrors: { workspace: "Choose a workspace" } },
    })
    const wrong = await handled(
      h.auth,
      consentRequest(screen, "approve", {}, { workspace: "zeta" }),
    )

    expect(wrong.status).toBe(400)
    expect(wrong.headers.get("location")).toBeNull()
    expect(consent.seen.at(-1)?.fieldErrors).toEqual({
      workspace: "Choose a workspace",
    })
    expect(consent.seen.at(-1)?.submitted).toEqual({ workspace: "zeta" })
    expect(h.idp.revoked).toEqual([])

    const right = await handled(
      h.auth,
      consentRequest(screen, "approve", {}, { workspace: "alpha" }),
    )

    expect(right.status).toBe(303)
    expect(locationOf(right).searchParams.get("code")).not.toBeNull()
  })

  it("never runs a hook before the form token and browser are verified", async () => {
    const hook = vi.fn(() => ({ ok: true as const }))
    const { h, screen } = await screenFor({ readConsentFields: hook })
    const forged = await handled(
      h.auth,
      consentRequest({ ...screen, csrf: "A".repeat(43) }),
    )

    expect(forged.status).toBe(400)
    expect(hook).not.toHaveBeenCalled()
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
  })

  it.each([
    [
      "throws",
      () => {
        throw new Error("down")
      },
    ],
    ["returns garbage", () => "yes"],
    [
      "returns oversized grantData",
      () => ({ ok: true, grantData: "x".repeat(5000) }),
    ],
    [
      "returns unserialisable grantData",
      () => ({ ok: true, grantData: { n: 1n } }),
    ],
    ["returns empty fieldErrors", () => ({ ok: false, fieldErrors: {} })],
  ])("ends the flow when readConsentFields %s", async (_label, hook) => {
    const { h, screen } = await screenFor({
      readConsentFields: hook as NonNullable<
        McpAuthOptions["readConsentFields"]
      >,
    })
    const response = await handled(h.auth, consentRequest(screen))

    expect(response.status).toBe(500)
    expect(response.headers.get("location")).toBeNull()
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
    expect(await h.store.listGrantsBySubject?.("person-1")).toEqual([])
  })

  it("does not run readConsentFields on a decline", async () => {
    const hook = vi.fn(() => ({ ok: true as const }))
    const { h, screen } = await screenFor({ readConsentFields: hook })
    const response = await handled(h.auth, consentRequest(screen, "deny"))

    expect(locationOf(response).searchParams.get("error")).toBe("access_denied")
    expect(hook).not.toHaveBeenCalled()
  })

  it("ends the sign-in when getConsentDetails throws or returns too much", async () => {
    for (const getConsentDetails of [
      () => {
        throw new Error("down")
      },
      () => ({ blob: "x".repeat(9000) }),
    ]) {
      const spy = pageSpy()
      const h = setup({
        getConsentDetails,
        renderErrorPage: spy.renderErrorPage,
      })
      const clientId = await registeredClientId(h.auth)

      await expect(reachConsent(h, clientId, newVerifier())).rejects.toThrow()
      expect(spy.pages.at(-1)?.reason).toBe("server_error")
      expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
    }
  })
})

describe("beforeGrant and afterGrant", () => {
  it("a refusal sends access_denied to the client and revokes upstream", async () => {
    const { h, screen } = await screenFor({
      beforeGrant: () => ({ allow: false, reason: "no_seat" }),
    })
    const response = await handled(h.auth, consentRequest(screen))
    const location = locationOf(response)

    expect(response.status).toBe(303)
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT)
    expect(location.searchParams.get("error")).toBe("access_denied")
    expect(location.searchParams.get("iss")).toBe(ISSUER)
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
    expect(await h.store.listGrantsBySubject?.("person-1")).toEqual([])
    expect(h.events).toContainEqual(
      expect.objectContaining({
        type: "authorization_refused",
        reason: "no_seat",
      }),
    )
  })

  it("a throwing or truthy-but-not-true beforeGrant refuses", async () => {
    for (const beforeGrant of [
      () => {
        throw new Error("down")
      },
      () => 1 as unknown as boolean,
      () => ({ allow: "yes" }) as unknown as boolean,
    ]) {
      const { h, screen } = await screenFor({ beforeGrant })
      const response = await handled(h.auth, consentRequest(screen))

      expect(locationOf(response).searchParams.get("error")).toBe(
        "access_denied",
      )
    }
  })

  it("receives frozen inputs including grantData and the request", async () => {
    let seen: unknown
    const { h, screen } = await screenFor({
      readConsentFields: () => ({ ok: true, grantData: { tier: "a" } }),
      beforeGrant: (context) => {
        seen = context

        return true
      },
    })

    await handled(h.auth, consentRequest(screen))
    expect(seen).toMatchObject({
      subject: "person-1",
      scopes: ["mcp"],
      grantData: { tier: "a" },
    })
    expect(Object.isFrozen(seen)).toBe(true)
  })

  it("awaits afterGrant before the client is answered", async () => {
    const order: string[] = []
    const { h, screen } = await screenFor({
      afterGrant: async ({ grant }) => {
        await new Promise((resolve) => setTimeout(resolve, 5))
        order.push(`after:${grant.subject}`)
        expect(JSON.stringify(grant)).not.toContain("sealed")
      },
    })
    const response = await handled(h.auth, consentRequest(screen))

    order.push("answered")
    expect(response.status).toBe(303)
    expect(order).toEqual(["after:person-1", "answered"])
  })

  it("a throwing afterGrant removes the grant, revokes upstream and sends server_error", async () => {
    const { h, clientId, verifier, screen } = await screenFor({
      afterGrant: () => {
        throw new Error("crm down")
      },
    })
    const response = await handled(h.auth, consentRequest(screen))
    const location = locationOf(response)

    expect(location.searchParams.get("error")).toBe("server_error")
    expect(location.searchParams.get("code")).toBeNull()
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
    expect(await h.store.listGrantsBySubject?.("person-1")).toEqual([])
    expect(clientId).not.toBe("")
    expect(verifier).not.toBe("")
  })
})

describe("scriptHashes", () => {
  it("adds sha256 hashes to the consent page's script-src", async () => {
    const hash = `sha256-${"A".repeat(43)}=`
    const { screen } = await screenFor({ scriptHashes: [hash] })
    const csp = screen.response.headers.get("content-security-policy") ?? ""

    expect(csp).toContain(`script-src '${hash}'`)
    expect(csp).toContain("default-src 'none'")
  })

  it.each([
    ["'unsafe-inline'"],
    ["sha384-abc"],
    [`sha256-${"A".repeat(43)}= 'unsafe-eval'`],
  ])("refuses %s", (value) => {
    expect(() => setup({ scriptHashes: [value] })).toThrow()
  })

  it("sends no script-src by default", async () => {
    const { screen } = await screenFor()

    expect(
      screen.response.headers.get("content-security-policy") ?? "",
    ).not.toContain("script-src")
  })
})
