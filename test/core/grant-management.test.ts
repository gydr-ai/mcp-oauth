import { describe, expect, it } from "vitest"

import { McpAuthConfigError, type McpAuthEvent } from "../../src/index.js"
import {
  connect,
  errorOf,
  handled,
  mcpRequest,
  newVerifier,
  obtainCode,
  readPair,
  registeredClientId,
  setup,
  tokenRequest,
} from "../support/harness.js"

async function live(h: ReturnType<typeof setup>) {
  const { clientId, pair } = await connect(h)
  const result = await h.auth.authenticate(mcpRequest(pair.access_token))

  if (!result.ok) throw new Error("expected ok")

  return { clientId, pair, result }
}

describe("upstream renewal", () => {
  it("passes the grant and subject to IdentityProvider.refresh", async () => {
    const h = setup()
    const { result } = await live(h)

    await result.getUpstreamAccessToken({ forceRefresh: true })
    expect(h.idp.refreshContexts).toEqual([
      { grantId: result.grantId, subject: "person-1" },
    ])
    expect(Object.isFrozen(h.idp.refreshContexts[0])).toBe(true)
  })

  it("serves the cached token normally and renews on forceRefresh", async () => {
    const h = setup()
    const { result } = await live(h)

    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-0")
    expect(h.idp.refreshCalls).toBe(0)
    expect(await result.getUpstreamAccessToken({ forceRefresh: true })).toBe(
      "upstream-access-1",
    )
    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-1")
    expect(h.idp.refreshCalls).toBe(1)
  })

  it("joins concurrent forced renewals into one refresh", async () => {
    const h = setup()
    const { result } = await live(h)

    h.idp.refreshDelayMs = 5

    const tokens = await Promise.all([
      result.getUpstreamAccessToken({ forceRefresh: true }),
      result.getUpstreamAccessToken({ forceRefresh: true }),
      h.auth.renewUpstream(result.grantId),
    ])

    expect(new Set(tokens).size).toBe(1)
    expect(h.idp.refreshCalls).toBe(1)
  })

  it("never uses a refresh token twice at once when a plain load is under way", async () => {
    const h = setup()
    const { result } = await live(h)

    h.clock.advance(3600)
    h.idp.refreshDelayMs = 5

    const [plain, forced] = await Promise.all([
      result.getUpstreamAccessToken(),
      result.getUpstreamAccessToken({ forceRefresh: true }),
    ])

    expect(plain).toBe("upstream-access-1")
    expect(forced).toBe("upstream-access-2")
  })

  it("renewUpstream drops the stored copy even when the renewal fails", async () => {
    const h = setup()
    const { result } = await live(h)

    h.idp.failRefresh = true
    await expect(h.auth.renewUpstream(result.grantId)).rejects.toThrow()
    expect(
      (await h.store.getGrant(result.grantId))?.upstreamAccessTokenExpiresAt,
    ).toBe(0)

    h.idp.failRefresh = false
    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-1")
  })

  it("renewUpstream refuses an unknown or ended grant", async () => {
    const h = setup()
    const { result } = await live(h)

    await expect(h.auth.renewUpstream("missing")).rejects.toThrow()
    await h.auth.revokeGrant(result.grantId)
    await expect(h.auth.renewUpstream(result.grantId)).rejects.toThrow()
    expect(h.idp.refreshCalls).toBe(0)
  })
})

describe("updateGrantData", () => {
  it("replaces the data seen by getGrantContext", async () => {
    const h = setup({ getGrantContext: ({ data }) => ({ data }) })
    const { pair, result } = await live(h)

    expect(await h.auth.updateGrantData(result.grantId, { plan: "b" })).toBe(
      true,
    )

    const again = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!again.ok) throw new Error("expected ok")

    expect(again.context).toEqual({ data: { plan: "b" } })
  })

  it("keeps no reference to the caller's object", async () => {
    const h = setup()
    const { result } = await live(h)
    const data = { plan: "b" }

    await h.auth.updateGrantData(result.grantId, data)
    data.plan = "changed"
    expect((await h.store.getGrant(result.grantId))?.data).toEqual({
      plan: "b",
    })
  })

  it("resolves false for an unknown grant and refuses oversized or non-JSON data", async () => {
    const h = setup()
    const { result } = await live(h)

    expect(await h.auth.updateGrantData("missing", { a: 1 })).toBe(false)
    await expect(
      h.auth.updateGrantData(result.grantId, "x".repeat(5000)),
    ).rejects.toThrow(TypeError)
    await expect(
      h.auth.updateGrantData(result.grantId, { n: 1n }),
    ).rejects.toThrow(TypeError)
  })

  it("cannot touch the sealed upstream tokens", async () => {
    const h = setup()
    const { result } = await live(h)
    const before = await h.store.getGrant(result.grantId)

    await h.auth.updateGrantData(result.grantId, {
      sealedUpstreamRefreshToken: "forged",
    })

    const after = await h.store.getGrant(result.grantId)

    expect(after?.sealedUpstreamRefreshToken).toBe(
      before?.sealedUpstreamRefreshToken,
    )
  })
})

describe("revokeGrantsForSubject", () => {
  it("ends every grant of the person and nobody else's", async () => {
    const h = setup()
    const one = await live(h)
    const two = await live(h)

    h.idp.login = { subject: "person-2" }

    const other = await live(h)

    expect(await h.auth.revokeGrantsForSubject("person-1")).toBe(2)

    for (const { pair } of [one, two]) {
      expect(
        (await h.auth.authenticate(mcpRequest(pair.access_token))).ok,
      ).toBe(false)
    }

    expect(
      (await h.auth.authenticate(mcpRequest(other.pair.access_token))).ok,
    ).toBe(true)
    expect(h.events).toContainEqual(
      expect.objectContaining({
        type: "grant_revoked",
        reason: "revoke_subject_call",
      }),
    )
  })

  it("ignores rows of another subject from a sloppy store", async () => {
    const h = setup()

    await live(h)

    const sloppy = setup({
      store: {
        ...h.store,
        listGrantsBySubject: () =>
          h.store.listGrantsBySubject?.("person-1") ?? Promise.resolve([]),
      },
    })

    expect(await sloppy.auth.revokeGrantsForSubject("person-2")).toBe(0)
  })

  it("throws a configuration error without listGrantsBySubject", async () => {
    const h = setup()
    const rest = { ...h.store }

    delete rest.listGrantsBySubject

    const plain = setup({ store: rest })

    await expect(plain.auth.revokeGrantsForSubject("person-1")).rejects.toThrow(
      McpAuthConfigError,
    )
  })
})

describe("grant_revoked event", () => {
  it("is emitted before the grant is deleted, with a frozen copy and no sealed tokens", async () => {
    const seenInStore: boolean[] = []
    const events: McpAuthEvent[] = []
    const h = setup({
      onEvent: async (event) => {
        events.push(event)

        if (event.type === "grant_revoked") {
          seenInStore.push(
            (await h.store.getGrant(event.grantId)) !== undefined,
          )
        }
      },
    })
    const { result } = await live(h)

    await h.auth.revokeGrant(result.grantId)

    const revoked = events.find((event) => event.type === "grant_revoked")

    expect(seenInStore).toEqual([true])
    expect(
      revoked?.type === "grant_revoked" && Object.isFrozen(revoked.grant),
    ).toBe(true)
    expect(JSON.stringify(revoked)).not.toMatch(/sealed|upstream/i)
  })
})

describe("beforeTokenIssue", () => {
  it("a refusal answers invalid_grant and leaves the refresh token usable", async () => {
    let allow = true
    const h = setup({ beforeTokenIssue: () => allow })
    const { clientId, pair } = await live(h)
    const refresh = () =>
      handled(
        h.auth,
        tokenRequest({
          grant_type: "refresh_token",
          client_id: clientId,
          refresh_token: pair.refresh_token,
        }),
      )

    allow = false
    expect(await errorOf(await refresh())).toBe("invalid_grant")

    h.clock.advance(60)
    allow = true

    const next = await refresh()

    expect(next.status).toBe(200)
    expect(h.events.map((e) => e.type)).not.toContain("refresh_token_replayed")
  })

  it("a throw answers 503 temporarily_unavailable", async () => {
    let fail = false
    const h = setup({
      beforeTokenIssue: () => {
        if (fail) throw new Error("down")

        return true
      },
    })
    const { clientId, pair } = await live(h)

    fail = true

    const response = await handled(
      h.auth,
      tokenRequest({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: pair.refresh_token,
      }),
    )

    expect(response.status).toBe(503)
    expect(await errorOf(response)).toBe("temporarily_unavailable")
  })

  it("runs for the code exchange too, before the code is spent", async () => {
    const calls: string[] = []
    let allow = false
    const h = setup({
      beforeTokenIssue: ({ grantType, grant }) => {
        calls.push(`${grantType}:${grant.subject}`)

        return allow ? { allow: true } : { allow: false, reason: "paused" }
      },
    })

    const clientId = await registeredClientId(h.auth)
    const verifier = newVerifier()
    const code = await obtainCode(h, clientId, verifier)
    const redeem = () =>
      handled(
        h.auth,
        tokenRequest({
          grant_type: "authorization_code",
          client_id: clientId,
          code,
          code_verifier: verifier,
        }),
      )

    expect(await errorOf(await redeem())).toBe("invalid_grant")
    expect(calls).toEqual(["authorization_code:person-1"])

    allow = true

    expect((await redeem()).status).toBe(200)
    expect(h.events.map((e) => e.type)).not.toContain(
      "authorization_code_replayed",
    )
  })

  it("a truthy non-true verdict refuses", async () => {
    const h = setup({ beforeTokenIssue: () => "yes" as unknown as boolean })

    await expect(connect(h)).rejects.toThrow("token 400")
  })

  it("token_issued carries the subject", async () => {
    const h = setup()
    const { clientId, pair } = await live(h)

    await readPair(
      await handled(
        h.auth,
        tokenRequest({
          grant_type: "refresh_token",
          client_id: clientId,
          refresh_token: pair.refresh_token,
        }),
      ),
    )
    expect(
      h.events.flatMap((e) => (e.type === "token_issued" ? [e.subject] : [])),
    ).toEqual(["person-1", "person-1"])
  })
})
