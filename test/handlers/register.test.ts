import { describe, expect, it } from "vitest"

import {
  errorOf,
  handled,
  ISSUER,
  registerClient,
  setup,
} from "../support/harness.js"

describe("POST /register (RFC 7591)", () => {
  it("registers a public client and never issues a secret", async () => {
    const { auth, store, events } = setup()
    const response = await registerClient(auth, {
      redirect_uris: [
        "https://client.example.org/cb",
        "http://127.0.0.1/cb",
        "http://[::1]/cb",
        "http://localhost/cb",
      ],
      client_name: "My Client",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: "mcp",
      logo_uri: "https://ignored.example/logo.png",
      software_statement: "ignored",
    })

    expect(response.status).toBe(201)
    expect(response.headers.get("cache-control")).toBe("no-store")

    const body: unknown = await response.json()

    expect(body).toMatchObject({
      client_name: "My Client",
      token_endpoint_auth_method: "none",
      response_types: ["code"],
    })
    expect(body).not.toHaveProperty("client_secret")
    expect(body).not.toHaveProperty("logo_uri")

    const clientId =
      typeof body === "object" && body !== null && "client_id" in body
        ? String(body.client_id)
        : ""

    expect(await store.getClient(clientId)).toMatchObject({
      kind: "dynamic",
      clientName: "My Client",
    })
    expect(events).toContainEqual({
      type: "client_registered",
      clientId,
      clientName: "My Client",
      redirectHosts: ["client.example.org", "127.0.0.1", "[::1]", "localhost"],
    })
  })

  it.each([
    [{}, "invalid_redirect_uri"],
    [{ redirect_uris: [] }, "invalid_redirect_uri"],
    [{ redirect_uris: "https://a.example/cb" }, "invalid_redirect_uri"],
    [
      { redirect_uris: ["http://client.example.org/cb"] },
      "invalid_redirect_uri",
    ],
    [{ redirect_uris: ["https://a.example/cb#frag"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["https://a.example/cb#"] }, "invalid_redirect_uri"],
    [
      { redirect_uris: ["https://user:pw@a.example/cb"] },
      "invalid_redirect_uri",
    ],
    [{ redirect_uris: ["myapp://callback"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["javascript:alert(1)"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["/relative"] }, "invalid_redirect_uri"],
    [
      { redirect_uris: [`https://a.example/${"x".repeat(2100)}`] },
      "invalid_redirect_uri",
    ],
    [
      {
        redirect_uris: Array.from(
          { length: 9 },
          (_, i) => `https://a.example/${i}`,
        ),
      },
      "invalid_redirect_uri",
    ],
    [
      {
        redirect_uris: ["https://a.example/cb"],
        token_endpoint_auth_method: "client_secret_basic",
      },
      "invalid_client_metadata",
    ],
    [
      { redirect_uris: ["https://a.example/cb"], grant_types: ["implicit"] },
      "invalid_client_metadata",
    ],
    [
      {
        redirect_uris: ["https://a.example/cb"],
        grant_types: ["refresh_token"],
      },
      "invalid_client_metadata",
    ],
    [
      { redirect_uris: ["https://a.example/cb"], response_types: ["token"] },
      "invalid_client_metadata",
    ],
    [
      { redirect_uris: ["https://a.example/cb"], scope: "admin" },
      "invalid_client_metadata",
    ],
    [
      { redirect_uris: ["https://a.example/cb"], client_name: "Evil‮gnp" },
      "invalid_client_metadata",
    ],
    [
      { redirect_uris: ["https://a.example/cb"], client_name: "line\nbreak" },
      "invalid_client_metadata",
    ],
    [
      { redirect_uris: ["https://a.example/cb"], client_name: "x".repeat(129) },
      "invalid_client_metadata",
    ],
    [
      { redirect_uris: ["https://a.example/cb"], client_name: 42 },
      "invalid_client_metadata",
    ],
  ])("refuses %o", async (body, error) => {
    const { auth } = setup()
    const response = await registerClient(auth, body)

    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe(error)
  })

  it("refuses a non-JSON content type, bad JSON, arrays and oversize bodies", async () => {
    const { auth } = setup()
    const send = (body: string, type = "application/json") =>
      handled(
        auth,
        new Request(`${ISSUER}/register`, {
          method: "POST",
          headers: { "Content-Type": type },
          body,
        }),
      )

    for (const response of [
      await send("{}", "text/plain"),
      await send("{nope"),
      await send("[]"),
      await send(
        JSON.stringify({
          redirect_uris: ["https://a.example/cb"],
          pad: "x".repeat(20_000),
        }),
      ),
    ]) {
      expect(response.status).toBe(400)
      expect(await errorOf(response)).toBe("invalid_client_metadata")
    }
  })

  it("honours the rate-limit hook", async () => {
    const seen: string[] = []
    const { auth, events } = setup({
      trustProxy: true,
      rateLimit: (key, scope) => {
        seen.push(`${scope}:${key}`)

        return Promise.resolve(false)
      },
    })
    const response = await handled(
      auth,
      new Request(`${ISSUER}/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Forwarded-For": "198.51.100.7, 203.0.113.9",
        },
        body: "{}",
      }),
    )

    expect(response.status).toBe(429)
    expect(seen).toEqual(["register:203.0.113.9"])
    expect(events).toContainEqual({
      type: "request_throttled",
      scope: "register",
    })
  })

  it("fails closed when the rate limiter throws, and uses getClientIp", async () => {
    const keys: string[] = []
    const { auth } = setup({
      getClientIp: () => "192.0.2.1",
      rateLimit: (key) => {
        keys.push(key)

        return Promise.reject(new Error("limiter down"))
      },
    })
    const response = await registerClient(auth)

    expect(response.status).toBe(429)
    expect(keys).toEqual(["192.0.2.1"])
  })

  it("uses an 'unknown' key without a proxy or resolver", async () => {
    const keys: string[] = []
    const { auth } = setup({
      rateLimit: (key) => {
        keys.push(key)

        return Promise.resolve(true)
      },
    })

    await handled(
      auth,
      new Request(`${ISSUER}/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Forwarded-For": "198.51.100.7",
        },
        body: JSON.stringify({ redirect_uris: ["https://a.example/cb"] }),
      }),
    )
    expect(keys).toEqual(["unknown"])
  })
})
