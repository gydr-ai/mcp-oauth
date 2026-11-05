import { beforeEach, describe, expect, it, vi } from "vitest"

const safeFetch = vi.hoisted(() =>
  vi.fn<
    (url: string, init?: RequestInit, options?: object) => Promise<Response>
  >(),
)

vi.mock("@gydr-ai/safe-fetch", () => ({ safeFetch }))

import { validateClientMetadata } from "../../src/core/client-metadata.js"
import { isMetadataDocumentClientId } from "../../src/helpers/client-fields.js"
import {
  authorizeParams,
  authorizeUrl,
  handled,
  newVerifier,
  REDIRECT,
  reachConsent,
  setup,
  tokenRequest,
} from "../support/harness.js"

const CLIENT_ID = "https://app.example.com/oauth/client.json"

function documentResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  })
}

const VALID = {
  client_id: CLIENT_ID,
  client_name: "Example App",
  redirect_uris: [REDIRECT, "myapp://ignored"],
  token_endpoint_auth_method: "none",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
}

async function authorize(h = setup(), clientId = CLIENT_ID) {
  return handled(
    h.auth,
    new Request(authorizeUrl(authorizeParams(clientId, newVerifier()))),
  )
}

beforeEach(() => {
  safeFetch.mockReset()
})

describe("metadata-document clients", () => {
  it("recognizes metadata-document client ids", () => {
    expect(isMetadataDocumentClientId(CLIENT_ID)).toBe(true)

    for (const id of [
      "https://app.example.com",
      "https://app.example.com/",
      "http://app.example.com/client.json",
      "https://app.example.com/a/../client.json",
      "https://app.example.com/./client.json",
      "https://user@app.example.com/client.json",
      "https://app.example.com/client.json#x",
      "https://APP.example.com/client.json",
      "client-abc",
      `https://app.example.com/${"x".repeat(2100)}`,
    ]) {
      expect(isMetadataDocumentClientId(id)).toBe(false)
    }
  })

  it("fetches through safeFetch with redirect error, timeout and size cap, then caches", async () => {
    const h = setup()

    safeFetch.mockResolvedValue(documentResponse(VALID))

    const first = await authorize(h)

    expect(first.status).toBe(302)
    expect(safeFetch).toHaveBeenCalledTimes(1)

    const [url, init, options] = safeFetch.mock.calls[0] ?? []

    expect(url).toBe(CLIENT_ID)
    expect(init).toMatchObject({ method: "GET", redirect: "error" })
    expect(options).toMatchObject({ timeoutMs: 4000, maxResponseBytes: 5120 })

    await authorize(h)
    expect(safeFetch).toHaveBeenCalledTimes(1)

    h.clock.advance(3601)
    safeFetch.mockResolvedValue(documentResponse(VALID))
    await authorize(h)
    expect(safeFetch).toHaveBeenCalledTimes(2)
  })

  it.each([
    ["max-age=60", 61, 2],
    ["max-age=60", 59, 1],
    ["no-store", 1, 2],
    ["no-cache", 1, 2],
    ["max-age=999999", 3601, 2],
    ["max-age=nonsense", 1, 2],
  ])(
    "honours Cache-Control %s, never beyond the configured lifetime (after %ds: %d downloads)",
    async (header, wait, downloads) => {
      const h = setup()

      safeFetch.mockImplementation(() =>
        Promise.resolve(
          documentResponse(VALID, {
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": header,
            },
          }),
        ),
      )
      await authorize(h)
      h.clock.advance(wait)
      await authorize(h)
      expect(safeFetch).toHaveBeenCalledTimes(downloads)
    },
  )

  it("refuses a client id that is the issuer's own URL", async () => {
    const issuer = "https://app.example.com/oauth/client.json"
    const h = setup({ issuer })

    safeFetch.mockResolvedValue(
      documentResponse({ ...VALID, client_id: issuer }),
    )

    const url = new URL(`${issuer}/authorize`)

    for (const [key, value] of Object.entries(
      authorizeParams(issuer, newVerifier()),
    )) {
      url.searchParams.set(key, value)
    }

    const response = await handled(h.auth, new Request(url))

    expect(response.status).toBe(400)
    expect(safeFetch).not.toHaveBeenCalled()
    expect(h.events).toContainEqual(
      expect.objectContaining({
        type: "client_metadata_refused",
        reason: "client_id_is_issuer",
      }),
    )
  })

  it("does not cache when the cache lifetime is 0", async () => {
    const h = setup({ lifetimes: { clientMetadataCache: 0 } })

    safeFetch.mockImplementation(() => Promise.resolve(documentResponse(VALID)))
    await authorize(h)
    await authorize(h)
    expect(safeFetch).toHaveBeenCalledTimes(2)
  })

  it("names the publishing host to the person", async () => {
    const h = setup()

    safeFetch.mockResolvedValue(documentResponse(VALID))

    const screen = await reachConsent(h, CLIENT_ID, newVerifier())

    expect(screen.html).toContain("app.example.com")
    expect(screen.html).not.toContain("Self-registered application")
  })

  it("lets a CIMD client redeem its code without a stored registration", async () => {
    const h = setup()

    safeFetch.mockResolvedValue(documentResponse(VALID))

    const verifier = newVerifier()
    const screen = await reachConsent(h, CLIENT_ID, verifier)
    const consent = await handled(
      h.auth,
      new Request("https://auth.example.com/consent", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: screen.cookie,
        },
        body: new URLSearchParams({
          interaction: screen.consentId,
          form_token: screen.csrf,
          choice: "approve",
        }).toString(),
      }),
    )
    const code =
      new URL(consent.headers.get("location") ?? "").searchParams.get("code") ??
      ""
    const token = await handled(
      h.auth,
      tokenRequest({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      }),
    )

    expect(token.status).toBe(200)
  })

  it.each([
    [
      "a mismatched client_id",
      { ...VALID, client_id: "https://evil.example/c.json" },
      "client_id_differs_from_url",
    ],
    [
      "a confidential client",
      { ...VALID, token_endpoint_auth_method: "client_secret_basic" },
      "confidential_client",
    ],
    [
      "a client secret",
      { ...VALID, client_secret: "s" },
      "confidential_client",
    ],
    [
      "no usable redirect",
      { ...VALID, redirect_uris: ["myapp://x"] },
      "redirect_uris_unusable",
    ],
    [
      "missing redirects",
      { ...VALID, redirect_uris: undefined },
      "redirect_uris_absent",
    ],
    [
      "bad grant types",
      { ...VALID, grant_types: ["client_credentials"] },
      "grant_types_unusable",
    ],
    [
      "bad response types",
      { ...VALID, response_types: ["token"] },
      "response_types_unusable",
    ],
    ["an array", [VALID], "not_an_object"],
  ])("rejects %s", async (_name, body, reason) => {
    const h = setup()

    safeFetch.mockResolvedValue(documentResponse(body))

    const response = await authorize(h)

    expect(response.status).toBe(400)
    expect(response.headers.get("location")).toBeNull()
    expect(h.events).toContainEqual({
      type: "client_metadata_refused",
      host: "app.example.com",
      reason,
    })
  })

  it("rejects an oversized document", async () => {
    const h = setup()

    safeFetch.mockResolvedValue(
      documentResponse({ ...VALID, pad: "x".repeat(70_000) }),
    )

    expect((await authorize(h)).status).toBe(400)
    expect(h.events).toContainEqual(
      expect.objectContaining({
        type: "client_metadata_refused",
        reason: "too_large",
      }),
    )
  })

  it("rejects non-200, non-JSON and fetch errors (SSRF refusals included)", async () => {
    const cases: [() => Promise<Response>, string][] = [
      [
        () => Promise.resolve(new Response("no", { status: 404 })),
        "status_404",
      ],
      [
        () => Promise.resolve(new Response("<html>", { status: 200 })),
        "invalid_json",
      ],
      [
        () =>
          Promise.reject(
            Object.assign(new Error("blocked"), { reason: "private_address" }),
          ),
        "private_address",
      ],
      [
        () =>
          Promise.reject(Object.assign(new Error("slow"), { code: "timeout" })),
        "timeout",
      ],
      [
        // A non-Error rejection, as a misbehaving fetcher might produce.
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- deliberately not an Error
        () => Promise.reject("weird"),
        "unreachable",
      ],
    ]

    for (const [impl, reason] of cases) {
      const h = setup()

      safeFetch.mockImplementationOnce(impl)
      expect((await authorize(h)).status).toBe(400)
      expect(h.events).toContainEqual(
        expect.objectContaining({ type: "client_metadata_refused", reason }),
      )
    }
  })

  it("rejects a body stream that errors", async () => {
    const h = setup()
    const body = new ReadableStream({
      pull(controller) {
        controller.error(
          Object.assign(new Error("reset"), { code: "network_error" }),
        )
      },
    })

    safeFetch.mockResolvedValue(new Response(body, { status: 200 }))
    expect((await authorize(h)).status).toBe(400)
    expect(h.events).toContainEqual(
      expect.objectContaining({ reason: "network_error" }),
    )
  })

  it("is ignored entirely when disabled", async () => {
    const h = setup({ clientIdMetadataDocuments: false })

    expect((await authorize(h)).status).toBe(400)
    expect(safeFetch).not.toHaveBeenCalled()
  })

  it("drops unusable redirect URIs and names with hidden characters", () => {
    const client = validateClientMetadata(
      CLIENT_ID,
      { ...VALID, client_name: "Bad\u0007Name" },
      1,
      {
        scopes: ["mcp"],
        limits: {
          clientNameLength: 128,
          redirectUris: 8,
          redirectUriLength: 2048,
          stateLength: 2048,
          scopeLength: 1024,
          registrationBytes: 16384,
          consentDetailsBytes: 8192,
          grantDataBytes: 4096,
          formBytes: 32768,
          clientMetadataBytes: 32768,
          clientMetadataTimeoutMs: 4000,
          clientMetadataFailures: 100,
          grantContextBytes: 4096,
        },
      },
    )

    expect(client.redirectUris).toEqual([REDIRECT])
    expect(client.clientName).toBeUndefined()
    expect(client.kind).toBe("metadata_document")
  })
})

describe("metadata-document validation (CIMD draft-03)", () => {
  const options = {
    scopes: ["mcp"],
    limits: {
      clientNameLength: 128,
      redirectUris: 8,
      redirectUriLength: 2048,
      stateLength: 2048,
      scopeLength: 1024,
      registrationBytes: 16384,
      consentDetailsBytes: 8192,
      grantDataBytes: 4096,
      formBytes: 32768,
      clientMetadataBytes: 5120,
      clientMetadataTimeoutMs: 4000,
      clientMetadataFailures: 10000,
      grantContextBytes: 4096,
    },
  }

  it.each([
    [["private_key_jwt"]],
    [["client_secret_basic", "private_key_jwt"]],
    ["none"],
    [[]],
  ])(
    "treats token_endpoint_auth_methods_supported %o without none as confidential",
    (methods) => {
      expect(() =>
        validateClientMetadata(
          CLIENT_ID,
          { ...VALID, token_endpoint_auth_methods_supported: methods },
          1,
          options,
        ),
      ).toThrow("confidential_client")
    },
  )

  it("accepts a plural list that includes none", () => {
    expect(
      validateClientMetadata(
        CLIENT_ID,
        {
          ...VALID,
          token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
        },
        1,
        options,
      ).clientId,
    ).toBe(CLIENT_ID)
  })

  it("leaves out redirect URIs that already carry a response parameter", () => {
    const client = validateClientMetadata(
      CLIENT_ID,
      {
        ...VALID,
        redirect_uris: [`${REDIRECT}?code=x`, `${REDIRECT}?iss=y`, REDIRECT],
      },
      1,
      options,
    )

    expect(client.redirectUris).toEqual([REDIRECT])
  })
})
