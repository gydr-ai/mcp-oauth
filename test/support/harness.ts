import { createHash, randomBytes } from "node:crypto"

import {
  createAesGcmSealer,
  createMcpAuth,
  createMemoryStore,
  type ErrorPageContext,
  type IdentityProvider,
  type McpAuth,
  type McpAuthEvent,
  type McpAuthOptions,
  type MemoryStoreOptions,
  type OAuthStore,
  type UpstreamLogin,
  type UpstreamRenewalContext,
  type UpstreamTokens,
} from "../../src/index.js"

export const ISSUER = "https://auth.example.com"
export const RESOURCE = "https://mcp.example.com/mcp"
export const REDIRECT = "https://client.example.org/callback"
export const LOOPBACK = "http://127.0.0.1/callback"

export function challengeOf(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url")
}

export function newVerifier(): string {
  return randomBytes(32).toString("base64url")
}

/** Run synchronous work and report its outcome as a promise. */
export function asPromise<T>(work: () => T): Promise<T> {
  try {
    return Promise.resolve(work())
  } catch (error) {
    return Promise.reject(error instanceof Error ? error : new Error("failed"))
  }
}

/** Drop one key from a parameter record. */
export function without(
  params: Record<string, string>,
  key: string,
): Record<string, string> {
  return Object.fromEntries(Object.entries(params).filter(([k]) => k !== key))
}

/** A controllable fake identity provider. */
export class FakeIdp implements IdentityProvider {
  readonly issued = new Map<
    string,
    { challenge: string; nonce: string; redirectUri: string }
  >()
  refreshCalls = 0
  refreshContexts: (UpstreamRenewalContext | undefined)[] = []
  refreshDelayMs = 0
  rotateRefreshTokens = true
  failRefresh = false
  failExchange = false
  login: Partial<UpstreamLogin> = {}
  withUpstreamTokens = true
  revoked: string[] = []
  lastAuthorization:
    | {
        state: string
        codeChallenge: string
        redirectUri: string
        nonce: string
      }
    | undefined
  #codeCounter = 0
  #refreshCounter = 0

  authorizationUrl(input: {
    state: string
    codeChallenge: string
    redirectUri: string
    nonce: string
  }): Promise<string> {
    return asPromise(() => {
      this.lastAuthorization = input
      const url = new URL("https://idp.example.net/authorize")

      url.searchParams.set("state", input.state)
      url.searchParams.set("code_challenge", input.codeChallenge)

      return url.toString()
    })
  }

  /** Simulate the person logging in: returns the IdP's code. */
  approveLogin(): string {
    const last = this.lastAuthorization

    if (last === undefined) throw new Error("no authorization started")

    this.#codeCounter += 1
    const code = `idp-code-${this.#codeCounter}`

    this.issued.set(code, {
      challenge: last.codeChallenge,
      nonce: last.nonce,
      redirectUri: last.redirectUri,
    })

    return code
  }

  exchangeCode(input: {
    code: string
    codeVerifier: string
    redirectUri: string
    nonce: string
    issuer?: string
  }): Promise<UpstreamLogin> {
    return asPromise((): UpstreamLogin => {
      const issued = this.issued.get(input.code)

      this.issued.delete(input.code)

      if (
        this.failExchange ||
        issued === undefined ||
        issued.challenge !== challengeOf(input.codeVerifier) ||
        issued.nonce !== input.nonce ||
        issued.redirectUri !== input.redirectUri
      ) {
        throw new Error("bad upstream exchange")
      }

      return {
        subject: "person-1",
        displayName: "Pat Example",
        claims: { sub: "person-1", email_verified: true },
        ...(this.withUpstreamTokens
          ? {
              refreshToken: "upstream-refresh-0",
              accessToken: "upstream-access-0",
              expiresIn: 3600,
            }
          : {}),
        ...this.login,
      }
    })
  }

  async refresh(
    refreshToken: string,
    context?: UpstreamRenewalContext,
  ): Promise<UpstreamTokens> {
    this.refreshCalls += 1
    this.refreshContexts.push(context)

    if (this.refreshDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.refreshDelayMs))
    }

    if (this.failRefresh) throw new Error("upstream refused")

    if (!refreshToken.startsWith("upstream-refresh-")) {
      throw new Error("unknown upstream refresh token")
    }

    this.#refreshCounter += 1

    return {
      accessToken: `upstream-access-${this.#refreshCounter}`,
      expiresIn: 3600,
      ...(this.rotateRefreshTokens
        ? { refreshToken: `upstream-refresh-${this.#refreshCounter}` }
        : {}),
    }
  }

  revoke(refreshToken: string): Promise<void> {
    this.revoked.push(refreshToken)

    return Promise.resolve()
  }
}

export class Clock {
  constructor(public value = Date.UTC(2026, 0, 1)) {}

  now = () => this.value

  advance(seconds: number): void {
    this.value += seconds * 1000
  }
}

export interface Harness {
  auth: McpAuth
  store: OAuthStore
  idp: FakeIdp
  clock: Clock
  events: McpAuthEvent[]
}

export function setup(
  overrides: Partial<McpAuthOptions> = {},
  storeOptions: Omit<MemoryStoreOptions, "now"> = {},
): Harness {
  const clock = new Clock()
  const idp = new FakeIdp()
  const store = createMemoryStore({ ...storeOptions, now: clock.now })
  const events: McpAuthEvent[] = []
  const auth = createMcpAuth({
    issuer: ISSUER,
    resource: RESOURCE,
    identityProvider: idp,
    store,
    sealer: createAesGcmSealer({
      keys: { k1: randomBytes(32) },
      currentKid: "k1",
    }),
    now: clock.now,
    onEvent: (event) => {
      events.push(event)
    },
    ...overrides,
  })

  return { auth, store, idp, clock, events }
}

export async function handled(
  auth: McpAuth,
  request: Request,
): Promise<Response> {
  const response = await auth.handle(request)

  if (response === undefined) throw new Error(`unrouted ${request.url}`)

  return response
}

export async function registerClient(
  auth: McpAuth,
  body: Record<string, unknown> = {
    redirect_uris: [REDIRECT],
    client_name: "Test Client",
    grant_types: ["authorization_code", "refresh_token"],
  },
): Promise<Response> {
  return handled(
    auth,
    new Request(`${ISSUER}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  )
}

export async function registeredClientId(
  auth: McpAuth,
  redirectUris: string[] = [REDIRECT],
): Promise<string> {
  const response = await registerClient(auth, {
    redirect_uris: redirectUris,
    client_name: "Test Client",
    grant_types: ["authorization_code", "refresh_token"],
  })
  const body: unknown = await response.json()

  if (
    typeof body !== "object" ||
    body === null ||
    !("client_id" in body) ||
    typeof body.client_id !== "string"
  ) {
    throw new Error("registration failed")
  }

  return body.client_id
}

export function authorizeUrl(params: Record<string, string>): string {
  const url = new URL(`${ISSUER}/authorize`)

  for (const [key, value] of Object.entries(params)) {
    url.searchParams.append(key, value)
  }

  return url.toString()
}

export function authorizeParams(
  clientId: string,
  verifier: string,
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: "code",
    code_challenge: challengeOf(verifier),
    code_challenge_method: "S256",
    resource: RESOURCE,
    state: "client-state-1",
    ...extra,
  }
}

/** `name=value` of the first Set-Cookie that sets a non-empty value. */
export function bindingCookie(response: Response): string {
  const cookie = response.headers
    .getSetCookie()
    .find((value) => /^__Host-mcp-auth-[^=]+=[^;]+;/.test(value))

  if (cookie === undefined) throw new Error("no binding cookie")

  return cookie.split(";")[0] ?? ""
}

export function hiddenField(html: string, name: string): string {
  const match = new RegExp(`name="${name}" value="([^"]*)"`).exec(html)

  if (match?.[1] === undefined) throw new Error(`no field ${name}`)

  return match[1]
}

export interface ConsentScreen {
  response: Response
  html: string
  cookie: string
  consentId: string
  csrf: string
}

/** /authorize → IdP login → /callback; returns the consent screen. */
export async function reachConsent(
  h: Harness,
  clientId: string,
  verifier: string,
  extra: Record<string, string> = {},
): Promise<ConsentScreen> {
  const start = await handled(
    h.auth,
    new Request(authorizeUrl(authorizeParams(clientId, verifier, extra))),
  )

  if (start.status !== 302) throw new Error(`authorize ${start.status}`)

  const cookie = bindingCookie(start)
  const state = h.idp.lastAuthorization?.state ?? ""
  const code = h.idp.approveLogin()
  const response = await handled(
    h.auth,
    new Request(`${ISSUER}/callback?state=${state}&code=${code}`, {
      headers: { Cookie: cookie },
    }),
  )
  const html = await response.text()

  return {
    response,
    html,
    cookie: bindingCookie(response),
    consentId: hiddenField(html, "interaction"),
    csrf: hiddenField(html, "form_token"),
  }
}

export function consentRequest(
  screen: Pick<ConsentScreen, "cookie" | "consentId" | "csrf">,
  decision = "approve",
  headers: Record<string, string> = {},
  fields: Record<string, string> = {},
): Request {
  return new Request(`${ISSUER}/consent`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: screen.cookie,
      Origin: ISSUER,
      ...headers,
    },
    body: new URLSearchParams({
      interaction: screen.consentId,
      form_token: screen.csrf,
      choice: decision,
      ...fields,
    }).toString(),
  })
}

/** Full browser flow; returns the authorization code. */
export async function obtainCode(
  h: Harness,
  clientId: string,
  verifier: string,
): Promise<string> {
  const screen = await reachConsent(h, clientId, verifier)
  const response = await handled(h.auth, consentRequest(screen))
  const location = new URL(response.headers.get("location") ?? "")
  const code = location.searchParams.get("code")

  if (code === null) throw new Error("no code")

  return code
}

export function tokenRequest(
  params: Record<string, string>,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${ISSUER}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(params).toString(),
  })
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  expires_in: number
  token_type: string
  scope: string
}

function isTokenPair(value: unknown): value is TokenPair {
  return (
    typeof value === "object" &&
    value !== null &&
    "access_token" in value &&
    typeof value.access_token === "string" &&
    "refresh_token" in value &&
    typeof value.refresh_token === "string"
  )
}

export async function readPair(response: Response): Promise<TokenPair> {
  const body: unknown = await response.json()

  if (!isTokenPair(body))
    throw new Error(`not a token pair: ${JSON.stringify(body)}`)

  return body
}

/** Register, consent, redeem: a live token pair. */
export async function connect(h: Harness): Promise<{
  clientId: string
  pair: TokenPair
}> {
  const clientId = await registeredClientId(h.auth)
  const verifier = newVerifier()
  const code = await obtainCode(h, clientId, verifier)
  const response = await handled(
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

  if (response.status !== 200) throw new Error(`token ${response.status}`)

  return { clientId, pair: await readPair(response) }
}

export async function errorOf(response: Response): Promise<string> {
  const body: unknown = await response.json()

  if (
    typeof body === "object" &&
    body !== null &&
    "error" in body &&
    typeof body.error === "string"
  ) {
    return body.error
  }

  throw new Error("no error field")
}

export function mcpRequest(token?: string): Request {
  return new Request(RESOURCE, {
    method: "POST",
    headers: token === undefined ? {} : { Authorization: `Bearer ${token}` },
  })
}

/** Captures every error page context a server renders. */
export function pageSpy(): {
  pages: ErrorPageContext[]
  renderErrorPage: (context: ErrorPageContext) => string
} {
  const pages: ErrorPageContext[] = []

  return {
    pages,
    renderErrorPage: (context) => {
      pages.push(context)

      return `<p>${context.reason}</p>`
    },
  }
}
