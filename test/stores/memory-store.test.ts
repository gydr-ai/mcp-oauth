import { describe, expect, it } from "vitest"

import { createMemoryStore } from "../../src/index.js"
import { Clock } from "../support/harness.js"

const grant = {
  grantId: "g1",
  clientId: "c1",
  subject: "s",
  scopes: ["mcp"],
  resource: "https://mcp.example.com/mcp",
  createdAt: 0,
}

describe("createMemoryStore atomicity", () => {
  it("parallel consumePendingAuthorization: exactly one wins", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })

    await store.putPendingAuthorization({
      id: "p1",
      clientId: "c1",
      clientKind: "dynamic",
      redirectUri: "https://a.example/cb",
      codeChallenge: "x",
      resource: "r",
      scopes: [],
      upstreamCodeVerifier: "v",
      upstreamNonce: "n",
      bindingHash: "b",
      expiresAt: clock.value + 1000,
    })

    const results = await Promise.all(
      Array.from({ length: 10 }, () => store.consumePendingAuthorization("p1")),
    )

    expect(results.filter((r) => r !== undefined)).toHaveLength(1)
  })

  it("parallel consumeConsentRequest: exactly one wins", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })

    await store.putConsentRequest({
      id: "c",
      grantId: "g",
      clientId: "c1",
      clientKind: "dynamic",
      redirectUri: "https://a.example/cb",
      codeChallenge: "x",
      resource: "r",
      scopes: [],
      subject: "s",
      csrfHash: "h",
      bindingHash: "b",
      expiresAt: clock.value + 1000,
    })

    const results = await Promise.all(
      Array.from({ length: 10 }, () => store.consumeConsentRequest("c")),
    )

    expect(results.filter((r) => r !== undefined)).toHaveLength(1)
  })

  it("parallel consumeAuthorizationCode: exactly one firstUse", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })

    await store.putAuthorizationCode({
      codeHash: "h",
      grantId: "g",
      clientId: "c",
      redirectUri: "https://a.example/cb",
      codeChallenge: "x",
      resource: "r",
      scopes: [],
      expiresAt: clock.value + 1000,
    })

    const results = await Promise.all(
      Array.from({ length: 10 }, () => store.consumeAuthorizationCode("h")),
    )

    expect(results.filter((r) => r?.firstUse === true)).toHaveLength(1)
    expect(results.filter((r) => r?.firstUse === false)).toHaveLength(9)
    expect(await store.consumeAuthorizationCode("missing")).toBeUndefined()
  })

  it("parallel useRefreshToken: exactly one without previousUsedAt", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })

    await store.putRefreshToken({
      tokenHash: "t",
      grantId: "g",
      clientId: "c",
      scopes: [],
      resource: "r",
      expiresAt: clock.value + 1000,
    })

    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        store.useRefreshToken("t", clock.value + i),
      ),
    )

    expect(results.filter((r) => r?.previousUsedAt === undefined)).toHaveLength(
      1,
    )
    expect(await store.useRefreshToken("missing", 0)).toBeUndefined()
  })

  it("putRefreshTokenReplacement keeps usedAt and is returned by later reads", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })

    await store.putRefreshToken({
      tokenHash: "t",
      grantId: "g",
      clientId: "c",
      scopes: [],
      resource: "r",
      expiresAt: clock.value + 1000,
    })
    await store.useRefreshToken("t", clock.value)
    await store.putRefreshTokenReplacement?.("t", "sealed-pair")

    expect(await store.getRefreshToken("t")).toMatchObject({
      usedAt: clock.value,
      sealedReplacement: "sealed-pair",
    })
    expect(await store.useRefreshToken("t", clock.value + 1)).toMatchObject({
      previousUsedAt: clock.value,
      record: { sealedReplacement: "sealed-pair" },
    })

    await store.putRefreshTokenReplacement?.("missing", "sealed-pair")
    expect(await store.getRefreshToken("missing")).toBeUndefined()
  })
})

describe("createMemoryStore lifecycle", () => {
  it("expires records on read", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })

    await store.putGrant({ ...grant, expiresAt: clock.value + 1000 })
    expect(await store.getGrant("g1")).toBeDefined()

    clock.advance(1)
    expect(await store.getGrant("g1")).toBeUndefined()
    expect(await store.updateGrant("g1", {})).toBe(false)
  })

  it("deleteGrant removes its tokens and codes", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })
    const expiresAt = clock.value + 10_000

    await store.putGrant({ ...grant, expiresAt })
    await store.putAccessToken({
      tokenHash: "a",
      grantId: "g1",
      clientId: "c1",
      scopes: [],
      resource: "r",
      expiresAt,
    })
    await store.putRefreshToken({
      tokenHash: "r",
      grantId: "g1",
      clientId: "c1",
      scopes: [],
      resource: "r",
      expiresAt,
    })
    await store.putAccessToken({
      tokenHash: "other",
      grantId: "g2",
      clientId: "c1",
      scopes: [],
      resource: "r",
      expiresAt,
    })
    expect(
      await store.updateGrant("g1", { upstreamAccessTokenExpiresAt: 5 }),
    ).toBe(true)
    expect((await store.getGrant("g1"))?.upstreamAccessTokenExpiresAt).toBe(5)

    await store.deleteGrant("g1")

    expect(await store.getGrant("g1")).toBeUndefined()
    expect(await store.getAccessToken("a")).toBeUndefined()
    expect(await store.getRefreshToken("r")).toBeUndefined()
    expect(await store.getAccessToken("other")).toBeDefined()

    await store.deleteAccessToken("other")
    expect(await store.getAccessToken("other")).toBeUndefined()
  })

  it("caches client metadata until its expiry", async () => {
    const clock = new Clock()
    const store = createMemoryStore({ now: clock.now })
    const client = {
      clientId: "https://a.example/c.json",
      redirectUris: ["https://a.example/cb"],
      kind: "metadata_document" as const,
      createdAt: 0,
    }

    await store.putCachedClientMetadata(
      client.clientId,
      client,
      clock.value + 1000,
    )
    expect(await store.getCachedClientMetadata(client.clientId)).toEqual(client)

    clock.advance(2)
    expect(await store.getCachedClientMetadata(client.clientId)).toBeUndefined()
  })

  it("bounds each collection, evicting expired entries first, then the oldest", async () => {
    const clock = new Clock()
    const store = createMemoryStore({
      now: clock.now,
      maxEntriesPerCollection: 2,
    })

    for (const id of ["a", "b", "c"]) {
      await store.putClient({
        clientId: id,
        redirectUris: [],
        kind: "dynamic",
        createdAt: 0,
      })
    }

    expect(await store.getClient("a")).toBeUndefined()
    expect(await store.getClient("c")).toBeDefined()

    await store.putGrant({
      ...grant,
      grantId: "old",
      expiresAt: clock.value + 1,
    })
    await store.putGrant({
      ...grant,
      grantId: "keep",
      expiresAt: clock.value + 9999,
    })
    clock.advance(1)
    await store.putGrant({
      ...grant,
      grantId: "new",
      expiresAt: clock.value + 9999,
    })

    expect(await store.getGrant("keep")).toBeDefined()
    expect(await store.getGrant("new")).toBeDefined()
  })

  it("works with the default clock", async () => {
    const store = createMemoryStore()

    await store.putGrant({ ...grant, expiresAt: Date.now() + 10_000 })
    expect(await store.getGrant("g1")).toBeDefined()
  })
})
