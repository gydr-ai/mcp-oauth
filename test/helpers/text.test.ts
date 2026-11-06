import { describe, expect, it } from "vitest"

import { trimTrailing } from "../../src/helpers/text.js"

describe("trimTrailing", () => {
  it("removes every trailing occurrence and nothing else", () => {
    expect(trimTrailing("https://a.example/x///", "/")).toBe(
      "https://a.example/x",
    )
    expect(trimTrailing("host.example..", ".")).toBe("host.example")
    expect(trimTrailing("////", "/")).toBe("")
    expect(trimTrailing("/a/b", "/")).toBe("/a/b")
  })

  it("stays linear on a long run of the character", () => {
    const started = performance.now()

    trimTrailing(`a${"/".repeat(200_000)}b`, "/")
    trimTrailing("/".repeat(200_000), "/")

    expect(performance.now() - started).toBeLessThan(100)
  })
})
