import { describe, expect, it } from "vitest"

import { GrantInactiveError, UpstreamTokenError } from "../../src/index.js"
import {
  connect,
  type Harness,
  mcpRequest,
  RESOURCE,
  setup,
} from "../support/harness.js"

const METADATA =
  "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

async function ok(h: Harness, token: string) {
  const result = await h.auth.authenticate(mcpRequest(token))

  if (!result.ok) throw new Error("expected an authenticated request")

  return result
}

describe("authenticate", () => {
  it("accepts a live token and exposes the grant", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    expect(result).toMatchObject({
      subject: "person-1",
      clientId,
      scopes: ["mcp"],
    })
  })

  it("401s with the RFC 9728 challenge when no token is sent (no error code)", async () => {
    const h = setup()
    const result = await h.auth.authenticate(mcpRequest())

    if (result.ok) throw new Error("expected failure")

    expect(result.response.status).toBe(401)
    expect(result.response.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${METADATA}", scope="mcp"`,
    )
  })

  it.each([
    ["a malformed token", "not-a-token"],
    ["an unknown token", "A".repeat(43)],
  ])("401s invalid_token for %s", async (_name, token) => {
    const h = setup()
    const result = await h.auth.authenticate(mcpRequest(token))

    if (result.ok) throw new Error("expected failure")

    expect(result.response.status).toBe(401)

    const header = result.response.headers.get("www-authenticate") ?? ""

    expect(header).toContain(`resource_metadata="${METADATA}"`)
    expect(header).toContain('error="invalid_token"')
  })

  it("refuses a non-Bearer scheme and an empty Bearer", async () => {
    const h = setup()

    for (const value of ["Basic abc", "Bearer ", "Bearer"]) {
      const result = await h.auth.authenticate(
        new Request(RESOURCE, { headers: { Authorization: value } }),
      )

      expect(result.ok).toBe(false)
    }
  })

  it("accepts a case-insensitive scheme", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(
      new Request(RESOURCE, {
        headers: { Authorization: `bearer ${pair.access_token}` },
      }),
    )

    expect(result.ok).toBe(true)
  })

  it("refuses an expired token", async () => {
    const h = setup()
    const { pair } = await connect(h)

    h.clock.advance(3601)
    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      false,
    )
  })

  it("refuses a token whose grant was revoked", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    await h.store.deleteGrant(result.grantId)

    // Even if a store keeps the token row, the grant check refuses it.
    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      false,
    )
  })

  it("refuses a token whose audience is another resource", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const get = h.store.getAccessToken.bind(h.store)

    h.store.getAccessToken = async (hash) => {
      const row = await get(hash)

      return row === undefined
        ? undefined
        : { ...row, resource: "https://other.example.com/mcp" }
    }

    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (result.ok) throw new Error("expected failure")

    expect(result.response.headers.get("www-authenticate")).toContain(
      "different resource",
    )
  })

  it("unauthorized() builds 401/403/400 challenges", () => {
    const h = setup()
    const forbidden = h.auth.unauthorized(mcpRequest(), {
      error: "insufficient_scope",
      description: 'needs "write"',
      scope: ["write"],
    })

    expect(forbidden.status).toBe(403)
    expect(forbidden.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${METADATA}", error="insufficient_scope", error_description="needs \\"write\\"", scope="write"`,
    )
    expect(
      h.auth.unauthorized(mcpRequest(), { error: "invalid_request" }).status,
    ).toBe(400)
    expect(h.auth.unauthorized(mcpRequest()).status).toBe(401)
  })
})

describe("getUpstreamAccessToken", () => {
  it("returns the stored upstream token without calling the IdP", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-0")
    expect(h.idp.refreshCalls).toBe(0)
  })

  it("refreshes near expiry, persists a rotated refresh token, then caches", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    h.clock.advance(3550)
    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-1")
    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-1")
    expect(h.idp.refreshCalls).toBe(1)

    const grant = await h.store.getGrant(result.grantId)

    expect(grant?.sealedUpstreamRefreshToken).toBeDefined()

    // The next refresh must use the ROTATED upstream token (the fake rejects
    // nothing here, but the second refresh must still succeed).
    h.clock.advance(3550)
    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-2")
  })

  it("single-flights concurrent refreshes per grant", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    h.idp.refreshDelayMs = 20
    h.clock.advance(3550)

    const tokens = await Promise.all(
      Array.from({ length: 5 }, () => result.getUpstreamAccessToken()),
    )

    expect(new Set(tokens).size).toBe(1)
    expect(h.idp.refreshCalls).toBe(1)
  })

  it("rejects with UpstreamTokenError when the IdP refresh fails", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    h.idp.failRefresh = true
    h.clock.advance(3550)

    await expect(result.getUpstreamAccessToken()).rejects.toBeInstanceOf(
      UpstreamTokenError,
    )
    expect(h.events.map((e) => e.type)).toContain(
      "upstream_token_refresh_failed",
    )
  })

  it("rejects with UpstreamTokenError when no upstream refresh token is held", async () => {
    const h = setup()

    h.idp.withUpstreamTokens = false

    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    await expect(result.getUpstreamAccessToken()).rejects.toBeInstanceOf(
      UpstreamTokenError,
    )
  })

  it("rejects with GrantInactiveError after revocation", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    await h.auth.revokeGrant(result.grantId)
    await expect(result.getUpstreamAccessToken()).rejects.toBeInstanceOf(
      GrantInactiveError,
    )
  })

  it("does not cache a token when the grant vanished during refresh", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)

    h.store.updateGrant = () => Promise.resolve(false)
    h.clock.advance(3550)
    await expect(result.getUpstreamAccessToken()).rejects.toBeInstanceOf(
      GrantInactiveError,
    )
  })

  it("falls back to a refresh when the stored copy cannot be opened", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await ok(h, pair.access_token)
    const grant = await h.store.getGrant(result.grantId)

    if (grant === undefined) throw new Error("no grant")

    await h.store.putGrant({
      ...grant,
      sealedUpstreamAccessToken: "v1.k1.garbage.garbage.garbage",
    })
    expect(await result.getUpstreamAccessToken()).toBe("upstream-access-1")
  })
})
