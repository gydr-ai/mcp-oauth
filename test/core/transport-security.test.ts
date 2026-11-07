import { describe, expect, it } from "vitest"

import type { McpAuth } from "../../src/index.js"
import {
  authorizeParams,
  authorizeUrl,
  handled,
  ISSUER,
  mcpRequest,
  newVerifier,
  registeredClientId,
  setup,
  tokenRequest,
} from "../support/harness.js"

const HSTS = "max-age=63072000; includeSubDomains"

/** One response of every kind the package builds. */
async function everyResponse(auth: McpAuth): Promise<Response[]> {
  const clientId = await registeredClientId(auth)
  const failed = await auth.authenticate(mcpRequest())

  if (failed.ok) throw new Error("expected a refusal")

  return [
    // JSON documents, cacheable.
    await handled(
      auth,
      new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
    ),
    // OAuth error.
    await handled(auth, tokenRequest({ client_id: clientId })),
    // CORS preflight and 405.
    await handled(auth, new Request(`${ISSUER}/token`, { method: "OPTIONS" })),
    await handled(auth, new Request(`${ISSUER}/token`)),
    // Redirect to the identity provider.
    await handled(
      auth,
      new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
    ),
    // HTML error page.
    await handled(auth, new Request(`${ISSUER}/authorize`)),
    // Revocation answer.
    await handled(
      auth,
      new Request(`${ISSUER}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: "x".repeat(43) }),
      }),
    ),
    // Resource-server refusals.
    failed.response,
    auth.unauthorized(mcpRequest(), { error: "insufficient_scope" }),
  ]
}

describe("Strict-Transport-Security", () => {
  it("is on every response the package builds", async () => {
    const { auth } = setup()
    const responses = await everyResponse(auth)
    const statuses = new Set(responses.map((r) => r.status))

    // The sample covers success, redirect, client error and page responses.
    expect([...statuses]).toEqual(
      expect.arrayContaining([200, 204, 302, 400, 401, 403, 405]),
    )

    for (const response of responses) {
      expect(response.headers.get("strict-transport-security")).toBe(HSTS)
    }
  })

  it("is left out only when explicitly turned off", async () => {
    const { auth } = setup({ strictTransportSecurity: false })

    for (const response of await everyResponse(auth)) {
      expect(response.headers.has("strict-transport-security")).toBe(false)
    }
  })

  it("leaves unrouted requests to the application", async () => {
    const { auth } = setup()

    expect(await auth.handle(new Request(`${ISSUER}/not-ours`))).toBeUndefined()
  })
})
