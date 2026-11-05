import { describe, expect, it } from "vitest"

import {
  connect,
  errorOf,
  handled,
  ISSUER,
  mcpRequest,
  registeredClientId,
  setup,
  tokenRequest,
} from "../support/harness.js"

function revoke(
  params: Record<string, string>,
  headers: Record<string, string> = {},
) {
  return new Request(`${ISSUER}/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(params).toString(),
  })
}

describe("revocation endpoint", () => {
  it("a refresh token ends its grant", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const response = await handled(
      h.auth,
      revoke({ token: pair.refresh_token, client_id: clientId }),
    )

    expect(response.status).toBe(200)
    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      false,
    )
    expect(h.events).toContainEqual(
      expect.objectContaining({
        type: "grant_revoked",
        reason: "revocation_request",
      }),
    )
  })

  it("revoking an access token deletes only that token", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)

    await handled(
      h.auth,
      revoke({
        token: pair.access_token,
        token_type_hint: "access_token",
        client_id: clientId,
      }),
    )
    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      false,
    )

    const refreshed = await handled(
      h.auth,
      tokenRequest({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: pair.refresh_token,
      }),
    )

    expect(refreshed.status).toBe(200)
  })

  it("finds an access token without a hint and a refresh token with a wrong hint", async () => {
    const h = setup()
    const { pair } = await connect(h)

    await handled(h.auth, revoke({ token: pair.access_token }))
    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      false,
    )

    await handled(
      h.auth,
      revoke({ token: pair.refresh_token, token_type_hint: "access_token" }),
    )
    expect(h.events.map((e) => e.type)).toContain("grant_revoked")
  })

  it("answers 200 for unknown and malformed tokens", async () => {
    const h = setup()

    for (const token of ["A".repeat(43), "garbage"]) {
      expect((await handled(h.auth, revoke({ token }))).status).toBe(200)
    }
  })

  it("does not revoke another client's token but still answers 200", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const other = await registeredClientId(h.auth)
    const response = await handled(
      h.auth,
      revoke({ token: pair.refresh_token, client_id: other }),
    )

    expect(response.status).toBe(200)
    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      true,
    )
  })

  it("refuses a missing token, client secrets and rate-limited calls", async () => {
    const h = setup()

    expect(await errorOf(await handled(h.auth, revoke({})))).toBe(
      "invalid_request",
    )

    const basic = await handled(
      h.auth,
      revoke({ token: "x" }, { Authorization: "Basic YTpi" }),
    )

    expect(basic.status).toBe(401)

    const limited = setup({ rateLimit: () => Promise.resolve(false) })

    expect((await handled(limited.auth, revoke({ token: "x" }))).status).toBe(
      429,
    )
  })
})

describe("revokeGrant (operator)", () => {
  it("kills every token and revokes upstream best effort", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!result.ok) throw new Error("expected ok")

    await h.auth.revokeGrant(result.grantId)

    expect((await h.auth.authenticate(mcpRequest(pair.access_token))).ok).toBe(
      false,
    )
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
    const revoked = h.events.find((event) => event.type === "grant_revoked")

    expect(revoked).toMatchObject({
      type: "grant_revoked",
      grantId: result.grantId,
      reason: "revoke_grant_call",
      grant: { grantId: result.grantId, subject: "person-1" },
    })
    expect(JSON.stringify(revoked)).not.toContain("sealed")
    expect(JSON.stringify(revoked)).not.toContain("upstream")
  })

  it("is a no-op for an unknown grant and tolerates an upstream failure", async () => {
    const h = setup()

    await h.auth.revokeGrant("missing")
    expect(h.events.map((e) => e.type)).not.toContain("grant_revoked")

    const { pair } = await connect(h)
    const result = await h.auth.authenticate(mcpRequest(pair.access_token))

    if (!result.ok) throw new Error("expected ok")

    h.idp.revoke = () => Promise.reject(new Error("idp down"))

    await expect(h.auth.revokeGrant(result.grantId)).resolves.toBeUndefined()
  })
})
