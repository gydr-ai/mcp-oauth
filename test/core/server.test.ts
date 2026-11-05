import { randomBytes } from "node:crypto"

import { describe, expect, it } from "vitest"

import {
  createAesGcmSealer,
  createMcpAuth,
  createMemoryStore,
  McpAuthConfigError,
  type McpAuthOptions,
} from "../../src/index.js"
import {
  FakeIdp,
  handled,
  ISSUER,
  RESOURCE,
  setup,
} from "../support/harness.js"

function base(overrides: Partial<McpAuthOptions> = {}): McpAuthOptions {
  return {
    issuer: ISSUER,
    resource: RESOURCE,
    identityProvider: new FakeIdp(),
    store: createMemoryStore(),
    sealer: createAesGcmSealer({
      keys: { a: randomBytes(32) },
      currentKid: "a",
    }),
    ...overrides,
  }
}

describe("protected resource metadata (RFC 9728)", () => {
  it("serves the path-suffixed and root documents", async () => {
    const { auth } = setup({ resourceName: "Example MCP" })

    for (const path of [
      "/.well-known/oauth-protected-resource/mcp",
      "/.well-known/oauth-protected-resource",
    ]) {
      const response = await handled(
        auth,
        new Request(`https://mcp.example.com${path}`),
      )

      expect(response.status).toBe(200)
      expect(response.headers.get("access-control-allow-origin")).toBe("*")
      expect(await response.json()).toEqual({
        resource: RESOURCE,
        authorization_servers: [ISSUER],
        scopes_supported: ["mcp"],
        bearer_methods_supported: ["header"],
        resource_name: "Example MCP",
      })
    }
  })
})

describe("authorization server metadata (RFC 8414)", () => {
  it("advertises exactly the supported profile", async () => {
    const { auth } = setup()
    const response = await handled(
      auth,
      new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
    )
    const body: unknown = await response.json()

    expect(body).toEqual({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      registration_endpoint: `${ISSUER}/register`,
      revocation_endpoint: `${ISSUER}/revoke`,
      scopes_supported: ["mcp"],
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      revocation_endpoint_auth_methods_supported: ["none"],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    })
  })

  it("omits registration when DCR is disabled and reflects CIMD off", async () => {
    const { auth } = setup({
      dynamicClientRegistration: false,
      clientIdMetadataDocuments: false,
    })
    const body: unknown = await (
      await handled(
        auth,
        new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
      )
    ).json()

    expect(body).not.toHaveProperty("registration_endpoint")
    expect(body).toHaveProperty("client_id_metadata_document_supported", false)
    expect(
      await auth.handle(new Request(`${ISSUER}/register`, { method: "POST" })),
    ).toBeUndefined()
  })

  it("places endpoints under an issuer path and serves the suffixed form", async () => {
    const auth = createMcpAuth(
      base({ issuer: "https://auth.example.com/oauth" }),
    )
    const response = await handled(
      auth,
      new Request(
        "https://auth.example.com/.well-known/oauth-authorization-server/oauth",
      ),
    )
    const body: unknown = await response.json()

    expect(body).toHaveProperty(
      "authorization_endpoint",
      "https://auth.example.com/oauth/authorize",
    )
    expect(
      await auth.handle(new Request("https://auth.example.com/authorize")),
    ).toBeUndefined()
  })
})

describe("routing", () => {
  it("falls through for unknown paths", async () => {
    const { auth } = setup()

    expect(await auth.handle(new Request(`${ISSUER}/mcp`))).toBeUndefined()
  })

  it("answers 405 with Allow for a wrong method", async () => {
    const { auth } = setup()
    const response = await handled(
      auth,
      new Request(`${ISSUER}/token`, { method: "GET" }),
    )

    expect(response.status).toBe(405)
    expect(response.headers.get("allow")).toBe("POST")
  })

  it("answers CORS preflight on browser-callable endpoints only", async () => {
    const { auth } = setup()
    const token = await handled(
      auth,
      new Request(`${ISSUER}/token`, { method: "OPTIONS" }),
    )

    expect(token.status).toBe(204)
    expect(token.headers.get("access-control-allow-methods")).toContain("POST")

    const consent = await handled(
      auth,
      new Request(`${ISSUER}/consent`, { method: "OPTIONS" }),
    )

    expect(consent.status).toBe(405)
  })

  it("turns an unexpected failure into a 500 without leaking it", async () => {
    const store = createMemoryStore()
    const events: string[] = []
    const auth = createMcpAuth(
      base({
        store: {
          ...store,
          putClient: () =>
            Promise.reject(
              new Error("database is down: secret-connection-string"),
            ),
        },
        onEvent: (event) => {
          events.push(event.type)
        },
      }),
    )
    const response = await handled(
      auth,
      new Request(`${ISSUER}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://a.example/cb"] }),
      }),
    )

    expect(response.status).toBe(500)
    expect(await response.text()).not.toContain("secret")
    expect(events).toContain("unexpected_failure")
  })

  it("survives a throwing onEvent hook", async () => {
    const auth = createMcpAuth(
      base({
        onEvent: () => {
          throw new Error("hook broke")
        },
      }),
    )
    const response = await handled(
      auth,
      new Request(`${ISSUER}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://a.example/cb"] }),
      }),
    )

    expect(response.status).toBe(201)
  })
})

describe("configuration", () => {
  it.each([
    [{ issuer: "http://auth.example.com" }, "https"],
    [{ issuer: "https://auth.example.com?x=1" }, "query"],
    [{ issuer: "https://auth.example.com#f" }, "query"],
    [{ issuer: "https://user@auth.example.com" }, "userinfo"],
    [{ issuer: "not a url" }, "absolute"],
    [{ issuer: "https://auth.example.com/a/" }, "normalized"],
    [{ resource: "http://mcp.example.com/mcp" }, "https"],
    [{ scopes: [] }, "scopes"],
    [{ scopes: ["bad scope"] }, "scopes"],
    [{ defaultScopes: ["other"] }, "defaultScopes"],
    [{ refreshReuseGraceSeconds: -1 }, "refreshReuseGraceSeconds"],
    [{ lifetimes: { accessToken: 0 } }, "accessToken"],
    [{ paths: { token: "token" } }, "absolute path"],
    [{ paths: { token: "/x", revoke: "/x" } }, "distinct"],
  ] satisfies [Partial<McpAuthOptions>, string][])(
    "rejects %o",
    (overrides, message) => {
      expect(() => createMcpAuth(base(overrides))).toThrow(McpAuthConfigError)
      expect(() => createMcpAuth(base(overrides))).toThrow(message)
    },
  )

  it("allows http localhost only with allowInsecureLocalhost", () => {
    const local = {
      issuer: "http://localhost:3000",
      resource: "http://localhost:3000/mcp",
    }

    expect(() => createMcpAuth(base(local))).toThrow(McpAuthConfigError)
    expect(() =>
      createMcpAuth(base({ ...local, allowInsecureLocalhost: true })),
    ).not.toThrow()
    expect(() =>
      createMcpAuth(
        base({
          issuer: "http://example.com",
          resource: RESOURCE,
          allowInsecureLocalhost: true,
        }),
      ),
    ).toThrow(McpAuthConfigError)
  })

  it("accepts a bare-origin issuer with a trailing slash", () => {
    expect(() =>
      createMcpAuth(base({ issuer: "https://auth.example.com/" })),
    ).not.toThrow()
  })
})
