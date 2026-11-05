import { describe, expect, it } from "vitest"

import {
  buildRedirect,
  isAcceptableRedirectUri,
  matchesAnyRedirectUri,
  redirectHostOf,
  redirectUriMatches,
  redirectUriProblem,
} from "../../src/helpers/redirect-uris.js"

describe("redirect URI registration rules", () => {
  it.each([
    "https://client.example.org/cb",
    "https://client.example.org:8443/cb?x=1",
    "http://127.0.0.1/cb",
    "http://127.0.0.1:43210/cb",
    "http://[::1]:5000/cb",
    "http://localhost/cb",
  ])("accepts %s", (uri) => {
    expect(isAcceptableRedirectUri(uri)).toBe(true)
  })

  it.each([
    ["http://client.example.org/cb", "disallowed_scheme"],
    ["http://127.0.0.2/cb", "disallowed_scheme"],
    ["http://localhost.example.com/cb", "disallowed_scheme"],
    ["ftp://client.example.org/cb", "disallowed_scheme"],
    ["myapp:/cb", "disallowed_scheme"],
    ["https://a.example/cb#x", "has_fragment"],
    ["https://a.example/cb#", "has_fragment"],
    ["https://u:p@a.example/cb", "has_credentials"],
    ["https://u@a.example/cb", "has_credentials"],
    ["not a url", "unparseable"],
    [`https://a.example/${"a".repeat(2100)}`, "over_length"],
  ])("refuses %s (%s)", (uri, problem) => {
    expect(redirectUriProblem(uri)).toBe(problem)
  })
})

describe("redirect URI matching", () => {
  it("matches exactly", () => {
    expect(
      redirectUriMatches("https://a.example/cb", "https://a.example/cb"),
    ).toBe(true)
  })

  it.each([
    "https://a.example/cb/",
    "https://a.example/CB",
    "https://a.example/cb?x=1",
    "https://a.example:443/cb",
    "https://a.example/cb/../cb",
    "https://evil.example/cb",
    "https://a.example.evil.example/cb",
    "https://a.example/cb#",
  ])("does not match %s against https://a.example/cb", (requested) => {
    expect(redirectUriMatches("https://a.example/cb", requested)).toBe(false)
  })

  it("ignores only the port for loopback", () => {
    expect(
      redirectUriMatches("http://127.0.0.1/cb", "http://127.0.0.1:51234/cb"),
    ).toBe(true)
    expect(
      redirectUriMatches("http://127.0.0.1:1/cb", "http://127.0.0.1:2/cb"),
    ).toBe(true)
    expect(redirectUriMatches("http://[::1]/cb", "http://[::1]:9999/cb")).toBe(
      true,
    )
    expect(
      redirectUriMatches("http://localhost/cb", "http://localhost:3000/cb"),
    ).toBe(true)
  })

  it.each([
    "http://127.0.0.1:5000/other",
    "http://127.0.0.1:5000/cb?x=1",
    "http://localhost:5000/cb",
    "http://127.0.0.1:5000/x/../cb",
    "https://127.0.0.1:5000/cb",
    "http://127.0.0.1:5000/cb#",
    "http://u@127.0.0.1:5000/cb",
  ])("loopback does not match %s against http://127.0.0.1/cb", (requested) => {
    expect(redirectUriMatches("http://127.0.0.1/cb", requested)).toBe(false)
  })

  it("never matches an unacceptable requested URI", () => {
    expect(redirectUriMatches("myapp:/cb", "myapp:/cb")).toBe(false)
    expect(redirectUriMatches("garbage", "http://127.0.0.1/cb")).toBe(false)
  })

  it("matches against any registered URI", () => {
    expect(
      matchesAnyRedirectUri(
        ["https://a.example/1", "https://a.example/2"],
        "https://a.example/2",
      ),
    ).toBe(true)
    expect(matchesAnyRedirectUri([], "https://a.example/2")).toBe(false)
  })
})

describe("redirect helpers", () => {
  it("shows the hostname for loopback and the host otherwise", () => {
    expect(redirectHostOf("http://127.0.0.1:5000/cb")).toBe("127.0.0.1")
    expect(redirectHostOf("https://a.example:8443/cb")).toBe("a.example:8443")
    expect(redirectHostOf("nope")).toBe("")
  })

  it("adds parameters next to an existing query", () => {
    const url = new URL(
      buildRedirect("https://a.example/cb?keep=1", {
        code: "c",
        state: undefined,
        iss: "https://auth.example.com",
      }),
    )

    expect(url.searchParams.get("keep")).toBe("1")
    expect(url.searchParams.get("code")).toBe("c")
    expect(url.searchParams.has("state")).toBe(false)
  })
})
