import { describe, expect, it } from "vitest"

import {
  connect,
  consentRequest,
  handled,
  mcpRequest,
  newVerifier,
  readPair,
  reachConsent,
  REDIRECT,
  registerClient,
  registeredClientId,
  RESOURCE,
  setup,
  tokenRequest,
} from "../support/harness.js"

const DAY = 86_400

function locationOf(response: Response): URL {
  return new URL(response.headers.get("location") ?? "about:blank")
}

/** A promise and the function that settles it. */
function gate(): { wait: Promise<void>; open: () => void } {
  let open = (): void => undefined
  const wait = new Promise<void>((resolve) => {
    open = resolve
  })

  return { wait, open }
}

async function grantIdOf(
  h: ReturnType<typeof setup>,
  accessToken: string,
): Promise<string> {
  const result = await h.auth.authenticate(mcpRequest(accessToken))

  if (!result.ok) throw new Error("not authenticated")

  return result.grantId
}

describe("a repeated consent submission while the first is still running", () => {
  it("waits for the first answer and gets the same redirect", async () => {
    const slow = gate()
    const entered = gate()
    const h = setup({
      afterGrant: async () => {
        entered.open()
        await slow.wait
      },
    })
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())

    const first = handled(h.auth, consentRequest(screen))

    await entered.wait

    // The double-click: same browser, same form, while `afterGrant` runs.
    const second = handled(h.auth, consentRequest(screen))

    setTimeout(slow.open, 300)

    const [a, b] = await Promise.all([first, second])

    expect(a.status).toBe(303)
    expect(b.status).toBe(303)
    expect(locationOf(b).searchParams.get("code")).toBe(
      locationOf(a).searchParams.get("code"),
    )
  })

  it("answers a forged repeat at once, without waiting", async () => {
    const slow = gate()
    const entered = gate()
    const h = setup({
      afterGrant: async () => {
        entered.open()
        await slow.wait
      },
    })
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())
    const first = handled(h.auth, consentRequest(screen))

    await entered.wait

    const started = Date.now()
    // Another browser: a different binding cookie never sees the answer.
    const forged = await handled(
      h.auth,
      consentRequest({ ...screen, cookie: `${screen.cookie}x` }),
    )

    expect(Date.now() - started).toBeLessThan(150)
    expect(forged.status).not.toBe(303)

    slow.open()
    await first
  })

  it("gives up after the replay window when the first never answers", async () => {
    const never = gate()
    const entered = gate()
    const h = setup({
      consentReplaySeconds: 1,
      afterGrant: async () => {
        entered.open()
        await never.wait
      },
    })
    const clientId = await registeredClientId(h.auth)
    const screen = await reachConsent(h, clientId, newVerifier())

    void handled(h.auth, consentRequest(screen))
    await entered.wait

    const started = Date.now()
    const second = await handled(h.auth, consentRequest(screen))

    expect(second.status).not.toBe(303)
    expect(Date.now() - started).toBeGreaterThanOrEqual(900)
    expect(Date.now() - started).toBeLessThan(3_000)

    never.open()
  })
})

describe("GrantRecord.redirectUri", () => {
  it("records where the approved authorization was sent, and shows it to afterGrant", async () => {
    const seen: (string | undefined)[] = []
    const h = setup({
      afterGrant: ({ grant }) => {
        seen.push(grant.redirectUri)
      },
    })
    const { pair } = await connect(h)
    const grant = await h.store.getGrant(await grantIdOf(h, pair.access_token))

    expect(grant?.redirectUri).toBe(REDIRECT)
    expect(seen).toEqual([REDIRECT])
  })
})

describe("lifetimes.grantIdle", () => {
  it("leaves the grant absolute when unset", async () => {
    const h = setup()
    const { pair } = await connect(h)
    const grant = await h.store.getGrant(await grantIdOf(h, pair.access_token))

    expect(grant?.expiresAt).toBe(grant!.createdAt + 90 * DAY * 1000)
  })

  it("ends an unused grant after the idle window", async () => {
    const h = setup({ lifetimes: { grant: 400 * DAY, grantIdle: 30 * DAY } })
    const { pair } = await connect(h)
    const grant = await h.store.getGrant(await grantIdOf(h, pair.access_token))

    expect(grant?.expiresAt).toBe(grant!.createdAt + 30 * DAY * 1000)
  })

  it("extends the grant on each refresh, never past the absolute limit", async () => {
    const h = setup({
      lifetimes: {
        grant: 45 * DAY,
        grantIdle: 30 * DAY,
        refreshToken: 40 * DAY,
      },
    })
    const { clientId, pair } = await connect(h)
    const grantId = await grantIdOf(h, pair.access_token)
    const createdAt = (await h.store.getGrant(grantId))!.createdAt
    const refresh = async (token: string) =>
      readPair(
        await handled(
          h.auth,
          tokenRequest({
            grant_type: "refresh_token",
            client_id: clientId,
            refresh_token: token,
            resource: RESOURCE,
          }),
        ),
      )

    h.clock.advance(10 * DAY)

    const second = await refresh(pair.refresh_token)

    expect((await h.store.getGrant(grantId))?.expiresAt).toBe(
      createdAt + 40 * DAY * 1000,
    )

    h.clock.advance(10 * DAY)
    await refresh(second.refresh_token)

    // 20 days + 30 idle = 50 days, capped at the 45-day absolute limit.
    expect((await h.store.getGrant(grantId))?.expiresAt).toBe(
      createdAt + 45 * DAY * 1000,
    )
  })

  it("refuses a grantIdle outside 0–34,560,000", () => {
    expect(() => setup({ lifetimes: { grantIdle: -1 } })).toThrow()
    expect(() => setup({ lifetimes: { grantIdle: 34_560_001 } })).toThrow()
  })
})

describe("defaultGrantTypes", () => {
  async function codeFor(h: ReturnType<typeof setup>, clientId: string) {
    const verifier = newVerifier()
    const screen = await reachConsent(h, clientId, verifier)
    const consent = await handled(h.auth, consentRequest(screen))
    const code = locationOf(consent).searchParams.get("code") ?? ""

    return handled(
      h.auth,
      tokenRequest({
        grant_type: "authorization_code",
        client_id: clientId,
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
        resource: RESOURCE,
      }),
    )
  }

  async function registerWithoutGrantTypes(h: ReturnType<typeof setup>) {
    const response = await registerClient(h.auth, {
      redirect_uris: [REDIRECT],
      client_name: "Quiet Client",
    })
    const body = (await response.json()) as { client_id: string }

    return body.client_id
  }

  it("follows RFC 7591 by default: no refresh token for a client that names no grant types", async () => {
    const h = setup()
    const tokens = (await (
      await codeFor(h, await registerWithoutGrantTypes(h))
    ).json()) as Record<string, unknown>

    expect(tokens.access_token).toBeTypeOf("string")
    expect(tokens.refresh_token).toBeUndefined()
  })

  it("gives such a client a refresh token when configured", async () => {
    const h = setup({
      defaultGrantTypes: ["authorization_code", "refresh_token"],
    })
    const tokens = (await (
      await codeFor(h, await registerWithoutGrantTypes(h))
    ).json()) as Record<string, unknown>

    expect(tokens.refresh_token).toBeTypeOf("string")
  })

  it("refuses a default without authorization_code or with an unknown type", () => {
    expect(() => setup({ defaultGrantTypes: ["refresh_token"] })).toThrow()
    expect(() =>
      setup({
        defaultGrantTypes: [
          "authorization_code",
          "implicit" as unknown as "refresh_token",
        ],
      }),
    ).toThrow()
  })
})
