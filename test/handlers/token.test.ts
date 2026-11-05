import { describe, expect, it } from "vitest"

import {
  connect,
  errorOf,
  type Harness,
  handled,
  mcpRequest,
  newVerifier,
  obtainCode,
  REDIRECT,
  RESOURCE,
  readPair,
  registeredClientId,
  setup,
  tokenRequest,
} from "../support/harness.js"

async function codeFor(h: Harness) {
  const clientId = await registeredClientId(h.auth)
  const verifier = newVerifier()
  const code = await obtainCode(h, clientId, verifier)

  return { clientId, verifier, code }
}

function redeem(
  clientId: string,
  code: string,
  verifier: string,
  extra: Record<string, string> = {},
) {
  return tokenRequest({
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
    ...extra,
  })
}

function grantRevoked(h: Harness): boolean {
  return h.events.some((event) => event.type === "grant_revoked")
}

describe("POST /token — authorization_code", () => {
  it("issues an opaque Bearer pair with no-store headers", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const response = await handled(
      h.auth,
      redeem(clientId, code, verifier, { resource: RESOURCE }),
    )

    expect(response.status).toBe(200)
    expect(response.headers.get("cache-control")).toBe("no-store")
    expect(response.headers.get("pragma")).toBe("no-cache")

    const pair = await readPair(response)

    expect(pair).toMatchObject({
      token_type: "Bearer",
      expires_in: 1800,
      scope: "mcp",
    })
    expect(pair.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(pair.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(pair.access_token).not.toBe(pair.refresh_token)
  })

  it("is single-use: a replayed code is refused AND revokes the grant", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const first = await handled(h.auth, redeem(clientId, code, verifier))
    const pair = await readPair(first)
    const replay = await handled(h.auth, redeem(clientId, code, verifier))

    expect(replay.status).toBe(400)
    expect(await errorOf(replay)).toBe("invalid_grant")
    expect(h.events.map((e) => e.type)).toContain("authorization_code_replayed")

    const auth = await h.auth.authenticate(mcpRequest(pair.access_token))

    expect(auth.ok).toBe(false)
  })

  it("lets exactly one of two parallel redemptions win", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const results = await Promise.all([
      handled(h.auth, redeem(clientId, code, verifier)),
      handled(h.auth, redeem(clientId, code, verifier)),
    ])

    expect(results.map((r) => r.status).sort()).toEqual([200, 400])
  })

  it.each([
    ["code_verifier", { code_verifier: newVerifier() }, "invalid_grant"],
    [
      "redirect_uri",
      { redirect_uri: "https://client.example.org/other" },
      "invalid_grant",
    ],
    [
      "resource",
      { resource: "https://other.example.com/mcp" },
      "invalid_target",
    ],
  ])(
    "a %s mismatch is refused (%o) with %s, without spending the code or ending the grant",
    async (_field, extra, expectedError) => {
      const h = setup()
      const { clientId, verifier, code } = await codeFor(h)
      const response = await handled(
        h.auth,
        redeem(clientId, code, verifier, extra),
      )

      expect(response.status).toBe(400)
      expect(await errorOf(response)).toBe(expectedError)
      expect(grantRevoked(h)).toBe(false)

      // The code is still good for the real client.
      const retry = await handled(h.auth, redeem(clientId, code, verifier))

      expect(retry.status).toBe(200)
    },
  )

  it("wrong verifiers never revoke, and the right one still succeeds", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const guess = await handled(
        h.auth,
        redeem(clientId, code, verifier, { code_verifier: newVerifier() }),
      )

      expect(await errorOf(guess)).toBe("invalid_grant")
    }

    expect(grantRevoked(h)).toBe(false)
    expect(h.idp.revoked).toEqual([])

    const right = await handled(h.auth, redeem(clientId, code, verifier))

    expect(right.status).toBe(200)
  })

  it("another client cannot spend the code or end the grant", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const other = await registeredClientId(h.auth)
    const response = await handled(h.auth, redeem(other, code, verifier))

    expect(await errorOf(response)).toBe("invalid_grant")
    expect(grantRevoked(h)).toBe(false)
    expect(
      (await handled(h.auth, redeem(clientId, code, verifier))).status,
    ).toBe(200)
  })

  it("redirect_uri is optional at /token and compared when sent", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const response = await handled(
      h.auth,
      tokenRequest({
        grant_type: "authorization_code",
        client_id: clientId,
        code,
        code_verifier: verifier,
      }),
    )

    expect(response.status).toBe(200)
  })

  it("accepts a resource differing only in scheme and host case", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const response = await handled(
      h.auth,
      redeem(clientId, code, verifier, {
        resource: "HTTPS://MCP.EXAMPLE.COM/mcp",
      }),
    )

    expect(response.status).toBe(200)
  })

  it("a fully valid replay ends the grant", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)

    await handled(h.auth, redeem(clientId, code, verifier))

    // A wrong verifier on a spent code is just refused.
    await handled(
      h.auth,
      redeem(clientId, code, verifier, { code_verifier: newVerifier() }),
    )
    expect(grantRevoked(h)).toBe(false)

    await handled(h.auth, redeem(clientId, code, verifier))
    expect(h.events).toContainEqual(
      expect.objectContaining({
        type: "grant_revoked",
        reason: "authorization_code_replay",
      }),
    )
  })

  it("of many concurrent valid redemptions exactly one wins", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const results = await Promise.all(
      Array.from({ length: 6 }, () =>
        handled(h.auth, redeem(clientId, code, verifier)),
      ),
    )

    expect(results.filter((r) => r.status === 200)).toHaveLength(1)
  })

  it("refuses an expired code", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)

    h.clock.advance(61)

    const response = await handled(h.auth, redeem(clientId, code, verifier))

    expect(await errorOf(response)).toBe("invalid_grant")
  })

  it("refuses an expired code still held by a lenient store", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const lenient = h.store.getAuthorizationCode.bind(h.store)

    h.clock.advance(30)

    // A store that does not evict on time: the server must still refuse.
    h.store.getAuthorizationCode = async (hash) => {
      const result = await lenient(hash)

      h.clock.advance(60)

      return result
    }

    const response = await handled(h.auth, redeem(clientId, code, verifier))

    expect(await errorOf(response)).toBe("invalid_grant")
    expect(h.events).toContainEqual(
      expect.objectContaining({ reason: "authorization_code_expired" }),
    )
  })

  it.each([
    [{ code: "" }, "invalid_request"],
    [{ code_verifier: "" }, "invalid_request"],
    [{ code: "not-a-real-code" }, "invalid_grant"],
  ])("refuses %o", async (extra, error) => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const response = await handled(
      h.auth,
      redeem(clientId, code, verifier, extra),
    )

    expect(await errorOf(response)).toBe(error)
  })

  it("refuses a code whose grant disappeared in between", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const granted = h.events.find((e) => e.type === "consent_approved")

    if (granted?.type !== "consent_approved") throw new Error("no grant")

    const lenient = h.store.getAuthorizationCode.bind(h.store)

    h.store.getAuthorizationCode = async (hash) => {
      const result = await lenient(hash)

      await h.store.deleteGrant(granted.grantId)

      return result
    }

    const response = await handled(h.auth, redeem(clientId, code, verifier))

    expect(await errorOf(response)).toBe("invalid_grant")
  })
})

describe("POST /token — client authentication and request shape", () => {
  it.each([[{ client_secret: "s" }], [{ client_assertion: "x" }]])(
    "refuses body credentials %o with 400 invalid_client and no challenge",
    async (extra) => {
      const h = setup()
      const { clientId, verifier, code } = await codeFor(h)
      const response = await handled(
        h.auth,
        redeem(clientId, code, verifier, extra),
      )

      expect(response.status).toBe(400)
      expect(response.headers.get("www-authenticate")).toBeNull()
      expect(await errorOf(response)).toBe("invalid_client")
    },
  )

  it.each([
    ["Basic YTpi", "Basic"],
    ["Bearer abc", "Bearer"],
    ["DPoP xyz", "DPoP"],
    ["bad\u0001scheme x", "Basic"],
  ])(
    "refuses an Authorization header %s with 401 and a %s challenge (RFC 6749 § 5.2)",
    async (header, scheme) => {
      const h = setup()
      const { clientId, verifier, code } = await codeFor(h)
      const response = await handled(
        h.auth,
        tokenRequest(
          {
            grant_type: "authorization_code",
            client_id: clientId,
            code,
            redirect_uri: REDIRECT,
            code_verifier: verifier,
          },
          { Authorization: header },
        ),
      )

      expect(response.status).toBe(401)
      expect(response.headers.get("www-authenticate")).toBe(scheme)
      expect(await errorOf(response)).toBe("invalid_client")
    },
  )

  it("refuses a missing or unknown client_id with 400 invalid_client", async () => {
    const h = setup()

    for (const params of [
      { grant_type: "refresh_token", refresh_token: "x" },
      {
        grant_type: "refresh_token",
        refresh_token: "x",
        client_id: "client-nope",
      },
    ]) {
      const response = await handled(h.auth, tokenRequest(params))

      expect(response.status).toBe(400)
      expect(response.headers.get("www-authenticate")).toBeNull()
      expect(await errorOf(response)).toBe("invalid_client")
    }
  })

  it("ignores repeated unknown parameters but refuses a repeated defined one", async () => {
    const h = setup()
    const { clientId, verifier, code } = await codeFor(h)
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      code_verifier: verifier,
    })

    body.append("x_extension", "1")
    body.append("x_extension", "2")

    const ok = await handled(
      h.auth,
      new Request("https://auth.example.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }),
    )

    expect(ok.status).toBe(200)

    for (const repeated of ["scope", "resource", "client_secret"]) {
      const twice = new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: "x",
      })

      twice.append(repeated, "a")
      twice.append(repeated, "b")

      expect(
        await errorOf(
          await handled(
            h.auth,
            new Request("https://auth.example.com/token", {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: twice.toString(),
            }),
          ),
        ),
      ).toBe("invalid_request")
    }
  })

  it("refuses duplicated parameters, wrong content type, bad grant types", async () => {
    const h = setup()
    const clientId = await registeredClientId(h.auth)
    const dup = new Request("https://auth.example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `client_id=${clientId}&grant_type=refresh_token&grant_type=refresh_token`,
    })

    expect(await errorOf(await handled(h.auth, dup))).toBe("invalid_request")

    const json = new Request("https://auth.example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    })

    expect(await errorOf(await handled(h.auth, json))).toBe("invalid_request")
    expect(
      await errorOf(
        await handled(
          h.auth,
          tokenRequest({ client_id: clientId, grant_type: "password" }),
        ),
      ),
    ).toBe("unsupported_grant_type")
    expect(
      await errorOf(
        await handled(h.auth, tokenRequest({ client_id: clientId })),
      ),
    ).toBe("invalid_request")

    const big = tokenRequest({ client_id: clientId, pad: "x".repeat(70_000) })

    expect(await errorOf(await handled(h.auth, big))).toBe("invalid_request")
  })

  it("refuses with 429 when rate limited", async () => {
    const h = setup({
      rateLimit: (_k, scope) => Promise.resolve(scope !== "token"),
    })
    const response = await handled(h.auth, tokenRequest({}))

    expect(response.status).toBe(429)
  })
})

describe("token endpoint: refresh", () => {
  function refresh(
    clientId: string,
    token: string,
    extra: Record<string, string> = {},
  ) {
    return tokenRequest({
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token: token,
      ...extra,
    })
  }

  it("rotates: a new pair, and the old access token keeps working", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const response = await handled(
      h.auth,
      refresh(clientId, pair.refresh_token),
    )
    const next = await readPair(response)

    expect(response.status).toBe(200)
    expect(next.refresh_token).not.toBe(pair.refresh_token)
    expect((await h.auth.authenticate(mcpRequest(next.access_token))).ok).toBe(
      true,
    )
  })

  it("returns another pair for a retry within the grace window", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)

    await handled(h.auth, refresh(clientId, pair.refresh_token))
    h.clock.advance(5)

    const retry = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(retry.status).toBe(200)
    expect(grantRevoked(h)).toBe(false)
  })

  it("ends the grant when a spent token returns after the window", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const next = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    h.clock.advance(11)

    const reuse = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(reuse.status).toBe(400)
    expect(await errorOf(reuse)).toBe("invalid_grant")
    expect(h.events.map((e) => e.type)).toContain("refresh_token_replayed")
    expect(h.idp.revoked).toEqual(["upstream-refresh-0"])
    // Every token of the grant is dead, including the legitimately rotated one.
    expect((await h.auth.authenticate(mcpRequest(next.access_token))).ok).toBe(
      false,
    )
    expect(
      (await handled(h.auth, refresh(clientId, next.refresh_token))).status,
    ).toBe(400)
  })

  it("with grace 0, any reuse revokes", async () => {
    const h = setup({ refreshReuseGraceSeconds: 0 })
    const { clientId, pair } = await connect(h)

    await handled(h.auth, refresh(clientId, pair.refresh_token))
    h.clock.advance(1)

    expect(
      (await handled(h.auth, refresh(clientId, pair.refresh_token))).status,
    ).toBe(400)
    expect(grantRevoked(h)).toBe(true)
  })

  it("does not let another client burn a refresh token", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const other = await registeredClientId(h.auth)
    const stolen = await handled(h.auth, refresh(other, pair.refresh_token))

    expect(await errorOf(stolen)).toBe("invalid_grant")
    expect(
      (await handled(h.auth, refresh(clientId, pair.refresh_token))).status,
    ).toBe(200)
  })

  it("allows narrowing scope and refuses widening", async () => {
    const h = setup({ scopes: ["read", "write"] })
    const { clientId, pair } = await connect(h)

    expect(pair.scope).toBe("read write")

    const narrowed = await readPair(
      await handled(
        h.auth,
        refresh(clientId, pair.refresh_token, { scope: "read" }),
      ),
    )

    expect(narrowed.scope).toBe("read")

    // Narrowing applies to that access token only (OAuth 2.1 § 4.3.1): the
    // new refresh token still carries the full grant.
    const full = await readPair(
      await handled(h.auth, refresh(clientId, narrowed.refresh_token)),
    )

    expect(full.scope).toBe("read write")

    const widened = await handled(
      h.auth,
      refresh(clientId, full.refresh_token, { scope: "read admin" }),
    )

    expect(await errorOf(widened)).toBe("invalid_scope")

    const blank = await handled(
      h.auth,
      refresh(clientId, full.refresh_token, { scope: "  " }),
    )

    expect(await errorOf(blank)).toBe("invalid_scope")
  })

  it("refuses an expired refresh token and a refresh past the grant cap", async () => {
    const h = setup({ lifetimes: { refreshToken: 100, grant: 150 } })
    const { clientId, pair } = await connect(h)

    h.clock.advance(90)

    const next = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    h.clock.advance(70)
    expect(
      await errorOf(
        await handled(h.auth, refresh(clientId, next.refresh_token)),
      ),
    ).toBe("invalid_grant")
  })

  it("refuses unknown, malformed and missing refresh tokens and a wrong resource", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)

    expect(
      await errorOf(await handled(h.auth, refresh(clientId, "A".repeat(43)))),
    ).toBe("invalid_grant")
    expect(
      await errorOf(await handled(h.auth, refresh(clientId, "short"))),
    ).toBe("invalid_grant")
    expect(
      await errorOf(
        await handled(
          h.auth,
          tokenRequest({ grant_type: "refresh_token", client_id: clientId }),
        ),
      ),
    ).toBe("invalid_request")
    expect(
      await errorOf(
        await handled(
          h.auth,
          refresh(clientId, pair.refresh_token, {
            resource: "https://other.example.com/mcp",
          }),
        ),
      ),
    ).toBe("invalid_target")
  })

  it("refuses when the store loses the token between read and use", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)

    h.store.useRefreshToken = () => Promise.resolve(undefined)

    expect(
      await errorOf(
        await handled(h.auth, refresh(clientId, pair.refresh_token)),
      ),
    ).toBe("invalid_grant")
  })

  it("refuses when the grant now belongs to another client", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const granted = h.events.find((e) => e.type === "consent_approved")

    if (granted?.type !== "consent_approved") throw new Error("no grant")

    const get = h.store.getRefreshToken.bind(h.store)

    h.store.getRefreshToken = async (hash) => {
      const row = await get(hash)

      await h.store.putGrant({
        grantId: granted.grantId,
        clientId: "someone-else",
        subject: "x",
        scopes: [],
        resource: RESOURCE,
        createdAt: 0,
        expiresAt: Number.MAX_SAFE_INTEGER,
      })

      return row
    }

    expect(
      await errorOf(
        await handled(h.auth, refresh(clientId, pair.refresh_token)),
      ),
    ).toBe("invalid_grant")
  })
})
