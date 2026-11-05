import { randomBytes } from "node:crypto"

import { describe, expect, it } from "vitest"

import { createAesGcmSealer, SealerError } from "../../src/index.js"

const k1 = randomBytes(32)
const k2 = randomBytes(32)

describe("createAesGcmSealer", () => {
  it("round-trips with the right AAD, with a fresh IV each time", async () => {
    const sealer = createAesGcmSealer({ keys: { k1 }, currentKid: "k1" })
    const a = await sealer.seal("secret-value", "grant-1")
    const b = await sealer.seal("secret-value", "grant-1")

    expect(a).not.toBe(b)
    expect(a).not.toContain("secret")
    expect(a.startsWith("v1.k1.")).toBe(true)
    expect(await sealer.open(a, "grant-1")).toBe("secret-value")
  })

  it("refuses the wrong AAD (a value moved to another grant)", async () => {
    const sealer = createAesGcmSealer({ keys: { k1 }, currentKid: "k1" })
    const sealed = await sealer.seal("secret-value", "grant-1")

    await expect(sealer.open(sealed, "grant-2")).rejects.toBeInstanceOf(
      SealerError,
    )
  })

  it("refuses tampering with any part", async () => {
    const sealer = createAesGcmSealer({ keys: { k1 }, currentKid: "k1" })
    const sealed = await sealer.seal("secret-value", "grant-1")
    const parts = sealed.split(".")

    for (const index of [2, 3, 4]) {
      const copy = [...parts]
      const part = copy[index] ?? ""
      const flipped = Buffer.from(part, "base64url")

      flipped[0] = (flipped[0] ?? 0) ^ 1
      copy[index] = flipped.toString("base64url")

      await expect(sealer.open(copy.join("."), "grant-1")).rejects.toThrow(
        SealerError,
      )
    }

    await expect(sealer.open("garbage", "grant-1")).rejects.toThrow(SealerError)
    await expect(
      sealer.open(`v2.${parts.slice(1).join(".")}`, "grant-1"),
    ).rejects.toThrow(SealerError)
    await expect(
      sealer.open(["v1", "k1", "AA", "AA", "AA"].join("."), "grant-1"),
    ).rejects.toThrow(SealerError)
  })

  it("rotates keys: old values open, new values use the current key", async () => {
    const before = createAesGcmSealer({ keys: { k1 }, currentKid: "k1" })
    const old = await before.seal("secret-value", "grant-1")
    const after = createAesGcmSealer({ keys: { k1, k2 }, currentKid: "k2" })

    expect(await after.open(old, "grant-1")).toBe("secret-value")
    expect((await after.seal("x", "g")).startsWith("v1.k2.")).toBe(true)

    const retired = createAesGcmSealer({ keys: { k2 }, currentKid: "k2" })

    await expect(retired.open(old, "grant-1")).rejects.toThrow(
      "key that is not configured",
    )
  })

  it("binds the key id: relabelling a value with another kid fails", async () => {
    const sealer = createAesGcmSealer({
      keys: { k1, k2: k1 },
      currentKid: "k1",
    })
    const sealed = await sealer.seal("secret-value", "grant-1")

    await expect(
      sealer.open(sealed.replace("v1.k1.", "v1.k2."), "grant-1"),
    ).rejects.toThrow(SealerError)
  })

  it("validates the key set", () => {
    expect(() =>
      createAesGcmSealer({ keys: { k1: randomBytes(16) }, currentKid: "k1" }),
    ).toThrow(TypeError)
    expect(() =>
      createAesGcmSealer({ keys: { "bad.kid": k1 }, currentKid: "bad.kid" }),
    ).toThrow(TypeError)
    expect(() =>
      createAesGcmSealer({ keys: { k1 }, currentKid: "k9" }),
    ).toThrow(TypeError)
  })

  it("copies keys so later mutation of the caller's buffer has no effect", async () => {
    const key = Uint8Array.from(randomBytes(32))
    const sealer = createAesGcmSealer({ keys: { k: key }, currentKid: "k" })
    const sealed = await sealer.seal("v", "a")

    key.fill(0)
    expect(await sealer.open(sealed, "a")).toBe("v")
  })
})
