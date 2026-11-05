import { describe, expect, it, vi } from "vitest"

const safeFetch = vi.hoisted(() =>
  vi.fn<
    (url: string, init?: RequestInit, options?: object) => Promise<Response>
  >(),
)

vi.mock("@gydr-ai/safe-fetch", () => ({ safeFetch }))

import { McpAuthConfigError } from "../../src/index.js"
import {
  authorizeParams,
  authorizeUrl,
  connect,
  handled,
  newVerifier,
  REDIRECT,
  registerClient,
  registeredClientId,
  setup,
} from "../support/harness.js"

const DOC_URL = "https://app.example.com/client.json"
const DOCUMENT = {
  client_id: DOC_URL,
  redirect_uris: [REDIRECT],
  grant_types: ["authorization_code", "refresh_token"],
}

function startAt(h: ReturnType<typeof setup>, clientId: string) {
  return handled(
    h.auth,
    new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
  )
}

describe("fetchClientMetadata option", () => {
  it("uses the supplied fetcher instead of the bundled one", async () => {
    const fetcher = vi.fn((_url: string, init: { signal: AbortSignal }) => {
      expect(init.signal).toBeInstanceOf(AbortSignal)

      return Promise.resolve(Response.json(DOCUMENT))
    })
    const h = setup({ fetchClientMetadata: fetcher })

    expect((await startAt(h, DOC_URL)).status).toBe(302)
    expect(fetcher).toHaveBeenCalledWith(DOC_URL, expect.anything())
    expect(safeFetch).not.toHaveBeenCalled()
  })

  it("still enforces the size cap on a custom fetcher", async () => {
    const h = setup({
      fetchClientMetadata: () =>
        Promise.resolve(
          Response.json({ ...DOCUMENT, padding: "x".repeat(2000) }),
        ),
      limits: { clientMetadataBytes: 1000 },
    })

    expect((await startAt(h, DOC_URL)).status).toBe(400)
    expect(h.events).toContainEqual(
      expect.objectContaining({ reason: "too_large" }),
    )
  })

  it("still enforces the deadline on a custom fetcher that ignores the signal", async () => {
    const h = setup({
      fetchClientMetadata: () => new Promise<Response>(() => {}),
      limits: { clientMetadataTimeoutMs: 20 },
    })

    expect((await startAt(h, DOC_URL)).status).toBe(400)
    expect(h.events).toContainEqual(
      expect.objectContaining({ reason: "timeout" }),
    )
  })

  it("still enforces the deadline while a custom fetcher's body trickles", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{"))
      },
    })
    const h = setup({
      fetchClientMetadata: () =>
        Promise.resolve(new Response(body, { status: 200 })),
      limits: { clientMetadataTimeoutMs: 20 },
    })

    expect((await startAt(h, DOC_URL)).status).toBe(400)
    expect(h.events).toContainEqual(
      expect.objectContaining({ reason: "timeout" }),
    )
  })

  it("still requires status 200 and the client_id check", async () => {
    for (const response of [
      new Response("", { status: 302, headers: { Location: "/x" } }),
      Response.json({ ...DOCUMENT, client_id: "https://other.example/c.json" }),
    ]) {
      const h = setup({
        fetchClientMetadata: () => Promise.resolve(response),
      })

      expect((await startAt(h, DOC_URL)).status).toBe(400)
    }
  })

  it("does not cache failures when clientMetadataFailure is 0", async () => {
    const fetcher = vi.fn(() =>
      Promise.resolve(new Response("", { status: 500 })),
    )
    const h = setup({
      fetchClientMetadata: fetcher,
      lifetimes: { clientMetadataFailure: 0 },
    })

    await startAt(h, DOC_URL)
    await startAt(h, DOC_URL)
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it("bounds the remembered failures", async () => {
    const fetcher = vi.fn(() =>
      Promise.resolve(new Response("", { status: 500 })),
    )
    const h = setup({
      fetchClientMetadata: fetcher,
      limits: { clientMetadataFailures: 2 },
    })

    for (const n of [1, 2, 3]) {
      await startAt(h, `https://app.example.com/c${n}.json`)
    }

    // c1 was forgotten when c3 was remembered, so it is fetched again.
    await startAt(h, "https://app.example.com/c1.json")
    await startAt(h, "https://app.example.com/c3.json")
    expect(fetcher).toHaveBeenCalledTimes(4)
  })
})

describe("cookiePrefix option", () => {
  it("names the binding cookie", async () => {
    const h = setup({ cookiePrefix: "__Host-acme-" })
    const response = await startAt(h, await registeredClientId(h.auth))

    expect(response.headers.getSetCookie()[0]).toMatch(
      /^__Host-acme-[0-9a-f]{20}=/,
    )
  })

  it.each(["acme-", "__Secure-acme-", "__Host-a;b", "__Host- x"])(
    "refuses %s",
    (cookiePrefix) => {
      expect(() => setup({ cookiePrefix })).toThrow(McpAuthConfigError)
    },
  )
})

describe("limits option", () => {
  it("applies custom limits", async () => {
    const h = setup({
      limits: { clientNameLength: 5, redirectUris: 1, stateLength: 4 },
    })

    expect(
      (
        await registerClient(h.auth, {
          redirect_uris: [REDIRECT],
          client_name: "Sixsix",
        })
      ).status,
    ).toBe(400)
    expect(
      (
        await registerClient(h.auth, {
          redirect_uris: [REDIRECT, `${REDIRECT}2`],
        })
      ).status,
    ).toBe(400)

    const registered: unknown = await (
      await registerClient(h.auth, { redirect_uris: [REDIRECT] })
    ).json()
    const clientId =
      typeof registered === "object" &&
      registered !== null &&
      "client_id" in registered &&
      typeof registered.client_id === "string"
        ? registered.client_id
        : ""
    const response = await handled(
      h.auth,
      new Request(
        authorizeUrl(
          authorizeParams(clientId, newVerifier(), { state: "12345" }),
        ),
      ),
    )

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
  })

  it.each([{ clientNameLength: 0 }, { redirectUris: -1 }, { formBytes: 1.5 }])(
    "refuses %o",
    (limits) => {
      expect(() => setup({ limits })).toThrow(McpAuthConfigError)
    },
  )
})

describe("default lifetimes", () => {
  it("issues 30-minute access tokens and 14-day refresh tokens", async () => {
    const h = setup()
    const { pair } = await connect(h)

    expect(pair.expires_in).toBe(1800)

    h.clock.advance(13 * 86_400)
    expect(
      (
        await h.auth.authenticate(
          new Request("https://mcp.example.com/mcp", {
            headers: { Authorization: `Bearer ${pair.access_token}` },
          }),
        )
      ).ok,
    ).toBe(false)
  })

  it("keeps a sign-in open for 15 minutes", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)

    await startAt(h, clientId)

    const stored = await h.store.getPendingAuthorization(
      h.idp.lastAuthorization?.state ?? "",
    )

    expect((stored?.expiresAt ?? 0) - h.clock.value).toBe(900_000)
  })
})
