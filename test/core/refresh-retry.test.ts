import { createHash, randomBytes } from "node:crypto"

import { describe, expect, it } from "vitest"

import { createAesGcmSealer, type OAuthStore } from "../../src/index.js"
import {
  connect,
  errorOf,
  type Harness,
  handled,
  mcpRequest,
  readPair,
  setup,
  tokenRequest,
} from "../support/harness.js"

function refresh(clientId: string, token: string): Request {
  return tokenRequest({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: token,
  })
}

function grantRevoked(h: Harness): boolean {
  return h.events.some((event) => event.type === "grant_revoked")
}

function hashOf(token: string): string {
  return createHash("sha256").update(token).digest("hex")
}

async function works(h: Harness, accessToken: string): Promise<boolean> {
  return (await h.auth.authenticate(mcpRequest(accessToken))).ok
}

describe("refresh retry window: one token chain", () => {
  it("answers a retry inside the window with the identical pair", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const first = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )
    const issued = h.events.filter((e) => e.type === "token_issued").length

    h.clock.advance(5)

    const retry = await handled(h.auth, refresh(clientId, pair.refresh_token))
    const again = await readPair(retry)

    expect(retry.status).toBe(200)
    expect(again.access_token).toBe(first.access_token)
    expect(again.refresh_token).toBe(first.refresh_token)
    expect(again.scope).toBe(first.scope)
    expect(again.expires_in).toBe(first.expires_in - 5)
    // Nothing new was minted.
    expect(h.events.filter((e) => e.type === "token_issued")).toHaveLength(
      issued,
    )
    expect(grantRevoked(h)).toBe(false)
    expect(await works(h, again.access_token)).toBe(true)

    // The single chain continues normally.
    const next = await handled(h.auth, refresh(clientId, again.refresh_token))

    expect(next.status).toBe(200)
  })

  it("ends the grant when the spent token returns after the window", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)

    await handled(h.auth, refresh(clientId, pair.refresh_token))
    h.clock.advance(5)

    const retried = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    h.clock.advance(6)

    const late = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(await errorOf(late)).toBe("invalid_grant")
    expect(h.events.map((e) => e.type)).toContain("refresh_token_replayed")
    expect(grantRevoked(h)).toBe(true)
    expect(await works(h, retried.access_token)).toBe(false)
  })

  it("attacker and victim end up sharing one chain, and its fork ends the grant", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    // The victim rotates first.
    const victim1 = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    h.clock.advance(3)

    // The attacker redeems a copy inside the window: same pair, no new chain.
    const attacker1 = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    expect(attacker1.refresh_token).toBe(victim1.refresh_token)

    // The victim rotates again; later the attacker uses the shared token.
    h.clock.advance(60)

    const victim2 = await readPair(
      await handled(h.auth, refresh(clientId, victim1.refresh_token)),
    )

    h.clock.advance(60)

    const attacker2 = await handled(
      h.auth,
      refresh(clientId, attacker1.refresh_token),
    )

    expect(await errorOf(attacker2)).toBe("invalid_grant")
    expect(grantRevoked(h)).toBe(true)
    expect(await works(h, victim2.access_token)).toBe(false)
  })

  it("ends the grant at once when the replacement has already been used", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const victim1 = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    h.clock.advance(1)
    // The victim already rotated the replacement...
    expect(
      (await handled(h.auth, refresh(clientId, victim1.refresh_token))).status,
    ).toBe(200)
    h.clock.advance(1)

    // ...so a copy of the first token, even inside its window, is a replay.
    const copy = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(await errorOf(copy)).toBe("invalid_grant")
    expect(h.events.map((e) => e.type)).toContain("refresh_token_replayed")
    expect(grantRevoked(h)).toBe(true)
  })

  it("gives simultaneous retries the same pair", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const first = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    h.clock.advance(2)

    const retries = await Promise.all(
      [1, 2, 3].map(() =>
        handled(h.auth, refresh(clientId, pair.refresh_token)),
      ),
    )
    const pairs = await Promise.all(retries.map((r) => readPair(r)))

    expect(pairs.map((p) => p.refresh_token)).toEqual([
      first.refresh_token,
      first.refresh_token,
      first.refresh_token,
    ])
    expect(grantRevoked(h)).toBe(false)
  })

  it("never issues two pairs for simultaneous first uses", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const responses = await Promise.all([
      handled(h.auth, refresh(clientId, pair.refresh_token)),
      handled(h.auth, refresh(clientId, pair.refresh_token)),
    ])
    const winners = responses.filter((r) => r.status === 200)
    const waiting = responses.filter((r) => r.status === 503)

    expect(winners.length + waiting.length).toBe(2)
    expect(winners.length).toBeGreaterThan(0)

    for (const response of waiting) {
      expect(await errorOf(response)).toBe("temporarily_unavailable")
    }

    const tokens = new Set(
      (await Promise.all(winners.map((r) => readPair(r)))).map(
        (p) => p.refresh_token,
      ),
    )

    expect(tokens.size).toBe(1)

    // A retry once the exchange finished gets that same pair.
    const retry = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    expect(tokens.has(retry.refresh_token)).toBe(true)
    expect(grantRevoked(h)).toBe(false)
  })

  it("refuses a retry whose replacement is gone, without ending the grant", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)
    const first = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )
    const record = await h.store.getRefreshToken(hashOf(first.refresh_token))

    if (record === undefined) throw new Error("no record")

    await h.store.putRefreshToken({ ...record, expiresAt: 0 })

    const retry = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(await errorOf(retry)).toBe("invalid_grant")
    expect(grantRevoked(h)).toBe(false)
  })

  it("refuses a malformed replacement", async () => {
    const sealer = createAesGcmSealer({
      keys: { k1: randomBytes(32) },
      currentKid: "k1",
    })
    const h = setup({ sealer })
    const { clientId, pair } = await connect(h)

    await handled(h.auth, refresh(clientId, pair.refresh_token))

    const hash = hashOf(pair.refresh_token)
    const spent = await h.store.getRefreshToken(hash)

    if (spent === undefined) throw new Error("no record")

    const aad = `${spent.grantId}#refresh-replacement#${hash}`

    for (const value of ["not json", JSON.stringify({ accessToken: 1 })]) {
      await h.store.putRefreshTokenReplacement?.(
        hash,
        await sealer.seal(value, aad),
      )

      const retry = await handled(h.auth, refresh(clientId, pair.refresh_token))

      expect(await errorOf(retry)).toBe("invalid_grant")
    }

    expect(grantRevoked(h)).toBe(false)
  })

  it("answers a 503 while the first exchange has not stored its pair", async () => {
    const h = setup()
    const { clientId, pair } = await connect(h)

    // Spend the token as a first exchange would, without storing the pair.
    await h.store.useRefreshToken(hashOf(pair.refresh_token), h.clock.now())

    const retry = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(retry.status).toBe(503)
    expect(await errorOf(retry)).toBe("temporarily_unavailable")
    expect(grantRevoked(h)).toBe(false)
  })
})

describe("refresh retry window: store without putRefreshTokenReplacement", () => {
  function legacy(): Harness {
    const base = setup()
    const store: OAuthStore = { ...base.store }

    delete store.putRefreshTokenReplacement

    const h = setup({ store, now: base.clock.now })

    return { ...h, store, clock: base.clock }
  }

  it("answers a retry with an access token only", async () => {
    const h = legacy()
    const { clientId, pair } = await connect(h)
    const first = await readPair(
      await handled(h.auth, refresh(clientId, pair.refresh_token)),
    )

    h.clock.advance(5)

    const retry = await handled(h.auth, refresh(clientId, pair.refresh_token))
    const body: unknown = await retry.json()

    expect(retry.status).toBe(200)
    expect(body).toMatchObject({ token_type: "Bearer", scope: first.scope })
    expect(body).not.toHaveProperty("refresh_token")
    expect(grantRevoked(h)).toBe(false)

    // The one chain carries on; the spent token after the window is a replay.
    const next = await handled(h.auth, refresh(clientId, first.refresh_token))

    expect(next.status).toBe(200)

    h.clock.advance(10)
    expect(
      await errorOf(
        await handled(h.auth, refresh(clientId, pair.refresh_token)),
      ),
    ).toBe("invalid_grant")
    expect(grantRevoked(h)).toBe(true)
  })

  it("refuses the access-only retry once the grant is gone", async () => {
    const h = legacy()
    const { clientId, pair } = await connect(h)

    await handled(h.auth, refresh(clientId, pair.refresh_token))

    const grantId = (await h.store.getRefreshToken(hashOf(pair.refresh_token)))
      ?.grantId

    if (grantId === undefined) throw new Error("no grant")

    // Ended between the first check and the issuing, by another process.
    const getGrant = h.store.getGrant.bind(h.store)
    let reads = 0

    h.store.getGrant = (id) => {
      reads += 1

      return reads > 1 ? Promise.resolve(undefined) : getGrant(id)
    }

    const retry = await handled(h.auth, refresh(clientId, pair.refresh_token))

    expect(await errorOf(retry)).toBe("invalid_grant")
  })
})
