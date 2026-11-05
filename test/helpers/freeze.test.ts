import { describe, expect, it } from "vitest"

import { freezeDeep, frozenCopy } from "../../src/helpers/freeze.js"

describe("freezeDeep", () => {
  it("freezes nested arrays and objects in place", () => {
    const record = {
      clientId: "c",
      redirectUris: ["https://a.example/cb"],
      meta: { x: 1 },
    }

    freezeDeep(record)

    expect(Object.isFrozen(record)).toBe(true)
    expect(Object.isFrozen(record.redirectUris)).toBe(true)
    expect(Object.isFrozen(record.meta)).toBe(true)
  })
})

describe("frozenCopy", () => {
  it("returns an independent, deeply frozen copy", () => {
    const original = { scopes: ["read"] }
    const copy = frozenCopy(original)

    expect(copy).not.toBe(original)
    expect(Object.isFrozen(copy.scopes)).toBe(true)
    expect(Object.isFrozen(original.scopes)).toBe(false)
  })
})
