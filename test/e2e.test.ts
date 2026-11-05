import { randomBytes } from "node:crypto"

import { describe, expect, it } from "vitest"

import {
  createAesGcmSealer,
  createMcpAuth,
  createMemoryStore,
  createOidcProvider,
  type McpAuthEvent,
} from "../src/index.js"
import { FakeOidc } from "./support/fake-oidc.js"
import {
  challengeOf,
  hiddenField,
  ISSUER,
  newVerifier,
  RESOURCE,
  readPair,
} from "./support/harness.js"

const CLIENT_REDIRECT = "http://127.0.0.1/callback"

/** The cookie jar a browser would keep for the authorization server. */
class Jar {
  readonly #cookies = new Map<string, string>()

  absorb(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      const [pair = ""] = header.split(";")
      const index = pair.indexOf("=")
      const name = pair.slice(0, index)
      const value = pair.slice(index + 1)

      if (header.includes("Max-Age=0")) this.#cookies.delete(name)
      else this.#cookies.set(name, value)
    }
  }

  header(): string {
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join("; ")
  }
}

describe("end to end: an MCP client connects through a real OIDC provider", () => {
  it("discovers, registers, logs in, consents, calls, refreshes, revokes", async () => {
    const idp = await new FakeOidc().init()

    idp.options = { rotateRefreshTokens: true }

    const events: McpAuthEvent[] = []
    const auth = createMcpAuth({
      issuer: ISSUER,
      resource: RESOURCE,
      identityProvider: createOidcProvider({
        issuer: "https://idp.example.net",
        clientId: "mcp-gateway",
        clientSecret: "gateway-secret",
        scopes: ["openid", "email", "offline_access"],
        redirectUri: `${ISSUER}/callback`,
        fetch: idp.fetch,
      }),
      store: createMemoryStore(),
      sealer: createAesGcmSealer({
        keys: { "2026-01": randomBytes(32) },
        currentKid: "2026-01",
      }),
      onEvent: (event) => {
        events.push(event)
      },
    })
    const serve = async (request: Request) => {
      const response = await auth.handle(request)

      if (response !== undefined) return response

      // The host application's MCP endpoint.
      const result = await auth.authenticate(request)

      if (!result.ok) return result.response

      return Response.json({
        subject: result.subject,
        upstream: await result.getUpstreamAccessToken(),
      })
    }

    // 1. Unauthenticated call → 401 pointing at the resource metadata.
    const challenge = await serve(new Request(RESOURCE, { method: "POST" }))

    expect(challenge.status).toBe(401)

    const header = challenge.headers.get("www-authenticate") ?? ""
    const metadataUrl = /resource_metadata="([^"]+)"/.exec(header)?.[1] ?? ""
    const resourceMetadata: unknown = await (
      await serve(new Request(metadataUrl))
    ).json()

    expect(resourceMetadata).toHaveProperty("authorization_servers", [ISSUER])

    // 2. Authorization server metadata.
    const asMetadata = await (
      await serve(
        new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
      )
    ).json()

    if (typeof asMetadata !== "object" || asMetadata === null) throw new Error()

    // 3. Dynamic registration.
    const registration: unknown = await (
      await serve(
        new Request(`${ISSUER}/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client_name: "Desktop Agent",
            grant_types: ["authorization_code", "refresh_token"],
            redirect_uris: [CLIENT_REDIRECT],
          }),
        }),
      )
    ).json()
    const clientId =
      typeof registration === "object" &&
      registration !== null &&
      "client_id" in registration &&
      typeof registration.client_id === "string"
        ? registration.client_id
        : ""

    // 4. Browser: /authorize → IdP → /callback → consent → client.
    const jar = new Jar()
    const verifier = newVerifier()
    const redirectUri = "http://127.0.0.1:53682/callback"
    const authorize = new URL(`${ISSUER}/authorize`)

    authorize.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challengeOf(verifier),
      code_challenge_method: "S256",
      resource: RESOURCE,
      scope: "mcp",
      state: "xyz",
    }).toString()

    const toIdp = await serve(new Request(authorize))

    jar.absorb(toIdp)

    const callbackQuery = idp.login(toIdp.headers.get("location") ?? "")
    const consentPage = await serve(
      new Request(`${ISSUER}/callback?${callbackQuery.toString()}`, {
        headers: { Cookie: jar.header() },
      }),
    )

    jar.absorb(consentPage)

    const html = await consentPage.text()

    expect(html).toContain("Desktop Agent")
    expect(html).toContain("pat@example.net")
    expect(html).toContain("a program running on this device")

    const approved = await serve(
      new Request(`${ISSUER}/consent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: jar.header(),
          Origin: ISSUER,
        },
        body: new URLSearchParams({
          interaction: hiddenField(html, "interaction"),
          form_token: hiddenField(html, "form_token"),
          choice: "approve",
        }).toString(),
      }),
    )
    const back = new URL(approved.headers.get("location") ?? "")

    expect(`${back.origin}${back.pathname}`).toBe(
      "http://127.0.0.1:53682/callback",
    )
    expect(back.searchParams.get("state")).toBe("xyz")
    expect(back.searchParams.get("iss")).toBe(ISSUER)

    // 5. Token exchange.
    const pair = await readPair(
      await serve(
        new Request(`${ISSUER}/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: clientId,
            code: back.searchParams.get("code") ?? "",
            redirect_uri: redirectUri,
            code_verifier: verifier,
            resource: RESOURCE,
          }).toString(),
        }),
      ),
    )

    // 6. An authenticated MCP call; the upstream token never left the server.
    const call = await serve(
      new Request(RESOURCE, {
        method: "POST",
        headers: { Authorization: `Bearer ${pair.access_token}` },
      }),
    )

    expect(await call.json()).toEqual({
      subject: "person-42",
      upstream: "idp-access-0",
    })
    expect(JSON.stringify(pair)).not.toContain("idp-")

    // 7. Refresh rotation.
    const next = await readPair(
      await serve(
        new Request(`${ISSUER}/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: clientId,
            refresh_token: pair.refresh_token,
          }).toString(),
        }),
      ),
    )

    expect(next.access_token).not.toBe(pair.access_token)

    // 8. Revocation ends everything, including the upstream session.
    await serve(
      new Request(`${ISSUER}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: next.refresh_token,
          client_id: clientId,
        }).toString(),
      }),
    )

    const after = await serve(
      new Request(RESOURCE, {
        method: "POST",
        headers: { Authorization: `Bearer ${next.access_token}` },
      }),
    )

    expect(after.status).toBe(401)
    expect(idp.revoked).toEqual(["idp-refresh-0"])

    // No secret ever reached the event hook.
    const logged = JSON.stringify(events)

    for (const secret of [
      pair.access_token,
      pair.refresh_token,
      next.refresh_token,
      back.searchParams.get("code") ?? "",
      verifier,
      "idp-refresh-0",
      "idp-access-0",
      "gateway-secret",
    ]) {
      expect(logged).not.toContain(secret)
    }

    expect(events.map((e) => e.type)).toEqual([
      "client_registered",
      "authorization_started",
      "consent_approved",
      "token_issued",
      "token_issued",
      "grant_revoked",
    ])
  })
})
