import type {
  AfterGrantContext,
  BeforeGrantContext,
  BeforeTokenIssueContext,
  ConsentDetailsInput,
  ConsentFieldsResult,
  ReadConsentFieldsInput,
} from "./consent.js"
import type { McpAuthEventHandler, RateLimitScope } from "./events.js"
import type { IdentityProvider } from "./identity-provider.js"
import type { ConsentPageContext, ErrorPageContext } from "./pages.js"
import type {
  AllowRegistrationContext,
  AllowSubjectContext,
  AuthorizeClientContext,
  GrantContextInput,
  MappedSubject,
  MaybePromise,
  PolicyDecision,
  StaticClient,
  SubjectInput,
} from "./policy.js"
import type { ClientRecord } from "./records.js"
import type { SecretSealer } from "./sealer.js"
import type { OAuthStore } from "./store.js"

/**
 * Token and flow lifetimes, in seconds.
 *
 * @example
 * ```ts
 * import type {
 *   ClientMetadataFetcher,
 *   IdentityProvider,
 *   Lifetimes,
 *   Limits,
 *   McpAuthOptions,
 *   OAuthStore,
 *   RoutePaths,
 *   SecretSealer,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare const identityProvider: IdentityProvider
 * declare const store: OAuthStore
 * declare const sealer: SecretSealer
 * declare const egressFetch: ClientMetadataFetcher // must be SSRF-safe
 *
 * const lifetimes: Lifetimes = { accessToken: 900, refreshToken: 7 * 86_400 }
 * const limits: Limits = { clientNameLength: 64, redirectUris: 4 }
 * const paths: RoutePaths = { callback: "/oauth/callback" }
 *
 * export const options: McpAuthOptions = {
 *   issuer: "https://mcp.example.com",
 *   resource: "https://mcp.example.com/mcp",
 *   identityProvider,
 *   store,
 *   sealer,
 *   lifetimes,
 *   limits,
 *   paths,
 *   fetchClientMetadata: egressFetch,
 * }
 * ```
 */
export interface Lifetimes {
  /** Access token lifetime, 1 to 86,400. Default: 1800 (30 minutes). */
  readonly accessToken?: number
  /**
   * Refresh token lifetime, renewed with each rotation; 1 to 34,560,000
   * (400 days). Default: 1,209,600 (14 days).
   */
  readonly refreshToken?: number
  /**
   * Absolute limit on a grant: no token outlives it, and the person must
   * approve again afterwards; 1 to 34,560,000 (400 days). Default: 7,776,000
   * (90 days).
   */
  readonly grant?: number
  /**
   * Sliding limit on a grant: it also ends when it has not been renewed with
   * a refresh token for this long, and each renewal extends it again, never
   * beyond `grant`. 0 to 34,560,000; `0` disables. Default: 0.
   */
  readonly grantIdle?: number
  /** Authorization code lifetime, 1 to 600. Default: 60. */
  readonly authorizationCode?: number
  /** Time allowed for sign-in plus consent, 1 to 3600. Default: 900 (15 minutes). */
  readonly pendingAuthorization?: number
  /** Cache lifetime of a validated metadata document, 0 to 86,400; `0` disables. Default: 1800. */
  readonly clientMetadataCache?: number
  /**
   * How long a metadata-document URL that failed is not contacted again,
   * 0 to 3600; `0` disables. Default: 60.
   */
  readonly clientMetadataFailure?: number
}

/**
 * Size and count limits. Every value must be a positive integer.
 *
 * @example
 * ```ts
 * import type {
 *   ClientMetadataFetcher,
 *   IdentityProvider,
 *   Lifetimes,
 *   Limits,
 *   McpAuthOptions,
 *   OAuthStore,
 *   RoutePaths,
 *   SecretSealer,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare const identityProvider: IdentityProvider
 * declare const store: OAuthStore
 * declare const sealer: SecretSealer
 * declare const egressFetch: ClientMetadataFetcher // must be SSRF-safe
 *
 * const lifetimes: Lifetimes = { accessToken: 900, refreshToken: 7 * 86_400 }
 * const limits: Limits = { clientNameLength: 64, redirectUris: 4 }
 * const paths: RoutePaths = { callback: "/oauth/callback" }
 *
 * export const options: McpAuthOptions = {
 *   issuer: "https://mcp.example.com",
 *   resource: "https://mcp.example.com/mcp",
 *   identityProvider,
 *   store,
 *   sealer,
 *   lifetimes,
 *   limits,
 *   paths,
 *   fetchClientMetadata: egressFetch,
 * }
 * ```
 */
export interface Limits {
  /** Longest `client_name` accepted. Default: 128 characters. */
  readonly clientNameLength?: number
  /** Most redirect URIs per client. Default: 8. */
  readonly redirectUris?: number
  /** Longest redirect URI. Default: 2048 characters. */
  readonly redirectUriLength?: number
  /** Longest client `state` stored and returned. Default: 2048 characters. */
  readonly stateLength?: number
  /** Longest `scope` parameter. Default: 1024 characters. */
  readonly scopeLength?: number
  /** Largest registration request body. Default: 16 KiB. */
  readonly registrationBytes?: number
  /** Largest form body at the token, revocation and consent endpoints. Default: 32 KiB. */
  readonly formBytes?: number
  /** Largest Client ID Metadata Document. Default: 32 KiB. */
  readonly clientMetadataBytes?: number
  /** Deadline for downloading a metadata document. Default: 4000 ms. */
  readonly clientMetadataTimeoutMs?: number
  /** Most metadata-document URLs remembered as failed. Default: 10,000. */
  readonly clientMetadataFailures?: number
  /** Largest serialized `getGrantContext` result. Default: 4096 bytes. */
  readonly grantContextBytes?: number
  /** Largest serialized `getConsentDetails` result. Default: 8192 bytes. */
  readonly consentDetailsBytes?: number
  /** Largest serialized grant data (`GrantRecord.data`). Default: 4096 bytes. */
  readonly grantDataBytes?: number
}

/**
 * Downloads a Client ID Metadata Document. It receives the document URL and
 * an abort signal that fires at the configured deadline.
 *
 * It MUST be SSRF-safe: refuse private, loopback, link-local and cloud
 * metadata addresses, pin the connection to the address it checked (DNS
 * rebinding), and not follow redirects. The core still enforces the
 * deadline, the size cap, a `200` status and the document checks whatever
 * the fetcher does.
 *
 * @example
 * ```ts
 * import type {
 *   ClientMetadataFetcher,
 *   IdentityProvider,
 *   Lifetimes,
 *   Limits,
 *   McpAuthOptions,
 *   OAuthStore,
 *   RoutePaths,
 *   SecretSealer,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare const identityProvider: IdentityProvider
 * declare const store: OAuthStore
 * declare const sealer: SecretSealer
 * declare const egressFetch: ClientMetadataFetcher // must be SSRF-safe
 *
 * const lifetimes: Lifetimes = { accessToken: 900, refreshToken: 7 * 86_400 }
 * const limits: Limits = { clientNameLength: 64, redirectUris: 4 }
 * const paths: RoutePaths = { callback: "/oauth/callback" }
 *
 * export const options: McpAuthOptions = {
 *   issuer: "https://mcp.example.com",
 *   resource: "https://mcp.example.com/mcp",
 *   identityProvider,
 *   store,
 *   sealer,
 *   lifetimes,
 *   limits,
 *   paths,
 *   fetchClientMetadata: egressFetch,
 * }
 * ```
 */
export type ClientMetadataFetcher = (
  url: string,
  init: { readonly signal: AbortSignal },
) => Promise<Response>

/**
 * Paths the server answers, each matched exactly against the URL path. Each
 * must start with a single `/` and contain no `//`, backslash, `?`, `#`,
 * dot segment or whitespace; all must differ from each other, from the
 * metadata paths and from the resource's path.
 *
 * @example
 * ```ts
 * import type {
 *   ClientMetadataFetcher,
 *   IdentityProvider,
 *   Lifetimes,
 *   Limits,
 *   McpAuthOptions,
 *   OAuthStore,
 *   RoutePaths,
 *   SecretSealer,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare const identityProvider: IdentityProvider
 * declare const store: OAuthStore
 * declare const sealer: SecretSealer
 * declare const egressFetch: ClientMetadataFetcher // must be SSRF-safe
 *
 * const lifetimes: Lifetimes = { accessToken: 900, refreshToken: 7 * 86_400 }
 * const limits: Limits = { clientNameLength: 64, redirectUris: 4 }
 * const paths: RoutePaths = { callback: "/oauth/callback" }
 *
 * export const options: McpAuthOptions = {
 *   issuer: "https://mcp.example.com",
 *   resource: "https://mcp.example.com/mcp",
 *   identityProvider,
 *   store,
 *   sealer,
 *   lifetimes,
 *   limits,
 *   paths,
 *   fetchClientMetadata: egressFetch,
 * }
 * ```
 */
export interface RoutePaths {
  /** Authorization endpoint. Default: `<issuer path>/authorize`. */
  readonly authorize?: string
  /** Return point from the identity provider. Default: `<issuer path>/callback`. */
  readonly callback?: string
  /** Consent form target. Default: `<issuer path>/consent`. */
  readonly consent?: string
  /** Token endpoint. Default: `<issuer path>/token`. */
  readonly token?: string
  /** Registration endpoint. Default: `<issuer path>/register`. */
  readonly register?: string
  /** Revocation endpoint. Default: `<issuer path>/revoke`. */
  readonly revoke?: string
}

/**
 * Options for `createMcpAuth`.
 *
 * @example
 * ```ts
 * import type {
 *   ClientMetadataFetcher,
 *   IdentityProvider,
 *   Lifetimes,
 *   Limits,
 *   McpAuthOptions,
 *   OAuthStore,
 *   RoutePaths,
 *   SecretSealer,
 * } from "@gydr-ai/mcp-oauth"
 *
 * declare const identityProvider: IdentityProvider
 * declare const store: OAuthStore
 * declare const sealer: SecretSealer
 * declare const egressFetch: ClientMetadataFetcher // must be SSRF-safe
 *
 * const lifetimes: Lifetimes = { accessToken: 900, refreshToken: 7 * 86_400 }
 * const limits: Limits = { clientNameLength: 64, redirectUris: 4 }
 * const paths: RoutePaths = { callback: "/oauth/callback" }
 *
 * export const options: McpAuthOptions = {
 *   issuer: "https://mcp.example.com",
 *   resource: "https://mcp.example.com/mcp",
 *   identityProvider,
 *   store,
 *   sealer,
 *   lifetimes,
 *   limits,
 *   paths,
 *   fetchClientMetadata: egressFetch,
 * }
 * ```
 */
export interface McpAuthOptions {
  /**
   * This authorization server's issuer identifier (RFC 8414): an `https` URL
   * with no query or fragment. Endpoints live under it.
   */
  readonly issuer: string
  /**
   * Canonical URL of the MCP endpoint (RFC 8707 resource indicator); the
   * audience of every token.
   */
  readonly resource: string
  /** Supported scopes. Default: `["mcp"]`. */
  readonly scopes?: readonly string[]
  /** Scopes granted when a client asks for none. Default: all `scopes`. */
  readonly defaultScopes?: readonly string[]
  /**
   * Grant types a registered client or metadata document gets when it names
   * none. RFC 7591 § 2 reads an absent `grant_types` as
   * `["authorization_code"]`, so such a client receives no refresh token;
   * `["authorization_code", "refresh_token"]` gives it one. Must include
   * `authorization_code`. Default: `["authorization_code"]`.
   */
  readonly defaultGrantTypes?: readonly (
    "authorization_code" | "refresh_token"
  )[]
  /**
   * Plain-language description per scope, shown on the consent screen (and
   * escaped). Keys must be listed in `scopes`. Default: none.
   */
  readonly scopeDescriptions?: Readonly<Record<string, string>>
  /** Human-readable name of the resource (RFC 9728 `resource_name`). */
  readonly resourceName?: string
  /**
   * Pre-registered public clients, checked at start-up with the same rules
   * as registration. They take precedence over clients in the store.
   * Default: none.
   */
  readonly clients?: readonly StaticClient[]
  /** Where people sign in. */
  readonly identityProvider: IdentityProvider
  /** Persistence; see the atomicity contract on `OAuthStore`. */
  readonly store: OAuthStore
  /** Encrypts upstream tokens at rest. */
  readonly sealer: SecretSealer
  /** Replacement consent page. Default: the built-in page. */
  readonly renderConsentPage?: (context: ConsentPageContext) => string
  /** Replacement error page. Default: the built-in page. */
  readonly renderErrorPage?: (context: ErrorPageContext) => string
  /** Token and flow lifetimes. */
  readonly lifetimes?: Lifetimes
  /**
   * Seconds after a refresh token is used during which presenting it again
   * returns another token pair (a lost response, a retried request) instead
   * of ending the grant; `0` turns the window off. Default: 10.
   */
  readonly refreshReuseGraceSeconds?: number
  /** Accept Client ID Metadata Document client ids. Default: `true`. */
  readonly clientIdMetadataDocuments?: boolean
  /**
   * Serve RFC 7591 Dynamic Client Registration. Default: `true`, for clients
   * that do not support metadata documents yet. The MCP authorization
   * specification of 2026-07-28 deprecates it in favour of Client ID
   * Metadata Documents; set `false` to serve only those and pre-registered
   * clients.
   */
  readonly dynamicClientRegistration?: boolean
  /** Endpoint paths. Default: under the issuer's path. */
  readonly paths?: RoutePaths
  /** Size and count limits. */
  readonly limits?: Limits
  /**
   * Downloads metadata documents instead of the bundled SSRF-safe fetcher.
   * See {@link ClientMetadataFetcher} for what it must guarantee.
   * Default: `@gydr-ai/safe-fetch`.
   */
  readonly fetchClientMetadata?: ClientMetadataFetcher
  /**
   * Name prefix of the browser-binding cookie; must start with `__Host-`.
   * Default: `__Host-mcp-auth-`.
   */
  readonly cookiePrefix?: string
  /**
   * Called before an endpoint does any work. Only a resolved `true` lets the
   * request continue; anything else, a rejection or a throw answers 429.
   * `key` is the client IP from `getClientIp` or `trustProxy`; without
   * either, every request shares the key `"unknown"`. Default: no limit.
   */
  readonly rateLimit?: (key: string, scope: RateLimitScope) => Promise<boolean>
  /**
   * Take the client IP from the right-most `X-Forwarded-For` entry (the
   * address your own proxy saw). Enable only behind exactly one proxy you
   * control. Default: `false`.
   */
  readonly trustProxy?: boolean
  /**
   * Resolves the client IP used as the rate-limit key. Without it (or
   * `trustProxy`), all requests share one key.
   */
  readonly getClientIp?: (request: Request) => string | undefined
  /** Receives events; never sees a secret. */
  readonly onEvent?: McpAuthEventHandler
  /**
   * Extra policy at `/authorize`, called after every protocol check passed.
   * Return `false` to refuse: the client receives `access_denied`. It cannot
   * relax any check; a throwing hook refuses.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * export const authorizeClient: McpAuthOptions["authorizeClient"] = ({ client }) =>
   *   client.kind !== "dynamic"
   * ```
   */
  readonly authorizeClient?: (
    context: AuthorizeClientContext,
  ) => MaybePromise<PolicyDecision>
  /**
   * Extra policy at `/register`, called after the metadata passed
   * validation. Return `false` to refuse with 403. A throwing hook refuses.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * export const allowRegistration: McpAuthOptions["allowRegistration"] = ({ metadata }) =>
   *   typeof metadata.client_name === "string"
   * ```
   */
  readonly allowRegistration?: (
    context: AllowRegistrationContext,
  ) => MaybePromise<PolicyDecision>
  /**
   * Replace the subject and display name taken from the identity provider,
   * for example to use an e-mail address or an internal user id. Each field
   * is read once. The subject must be a non-empty string of at most 512
   * characters, trimmed, in NFC form and without invisible characters;
   * anything else ends the sign-in. An unusable display name is dropped.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * export const mapSubject: McpAuthOptions["mapSubject"] = ({ subject, claims }) =>
   *   typeof claims.email === "string"
   *     ? { subject: `idp|${subject}`, displayName: claims.email }
   *     : { subject: `idp|${subject}` }
   * ```
   */
  readonly mapSubject?: (input: SubjectInput) => MaybePromise<MappedSubject>
  /**
   * Extra policy after sign-in. Return `false` to stop: the person sees an
   * error page and the upstream refresh token is revoked. A throwing hook
   * refuses.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * export const allowSubject: McpAuthOptions["allowSubject"] = ({ claims }) =>
   *   claims.email_verified === true
   * ```
   */
  readonly allowSubject?: (
    context: AllowSubjectContext,
  ) => MaybePromise<PolicyDecision>
  /**
   * Extra policy for metadata-document client ids, called before anything is
   * downloaded. Return `false` to treat the client as unknown. A throwing
   * hook refuses.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * export const allowClientMetadataUrl: McpAuthOptions["allowClientMetadataUrl"] = (url) =>
   *   new URL(url).hostname.endsWith(".example.com")
   * ```
   */
  readonly allowClientMetadataUrl?: (
    url: string,
  ) => MaybePromise<PolicyDecision>
  /**
   * Data to expose as `AuthResult.context` for a grant, such as the
   * person's tenant. It must be JSON-serializable and at most
   * `limits.grantContextBytes` once serialized; it cannot change who the
   * token belongs to or what it may access. When it throws or returns
   * unusable data, `authenticate` returns a failure with a generic 500 and
   * emits `grant_context_failed`, without the error text.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * declare function tenantOf(subject: string): Promise<string>
   *
   * export const getGrantContext: McpAuthOptions["getGrantContext"] = async ({ subject }) => ({
   *   tenant: await tenantOf(subject),
   * })
   * ```
   */
  readonly getGrantContext?: (grant: GrantContextInput) => MaybePromise<unknown>
  /**
   * Data for the consent page, such as a list of plans or workspaces to
   * choose from. Called after sign-in; the result must be JSON-serializable
   * and at most `limits.consentDetailsBytes`. It is passed, frozen, to
   * `renderConsentPage` as `details` and to `readConsentFields`. A throw ends
   * the sign-in with an error page and revokes the upstream token.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * declare function workspacesOf(subject: string): Promise<string[]>
   *
   * export const getConsentDetails: McpAuthOptions["getConsentDetails"] = async ({ subject }) => ({
   *   workspaces: await workspacesOf(subject),
   * })
   * ```
   */
  readonly getConsentDetails?: (
    input: ConsentDetailsInput,
  ) => MaybePromise<unknown>
  /**
   * Read extra fields the consent page posted when the person approves.
   * Runs only after the form token and the browser cookie were verified.
   * Return `{ ok: true, grantData }` to continue (the data is stored on the
   * grant) or `{ ok: false, fieldErrors }` to show the page again without
   * using up the request. It cannot change scopes, resource, redirect or
   * subject. A throw or an invalid result ends the flow with an error page.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * export const readConsentFields: McpAuthOptions["readConsentFields"] = ({ form }) =>
   *   form.workspace === undefined || form.workspace === ""
   *     ? { ok: false, fieldErrors: { workspace: "Choose a workspace" } }
   *     : { ok: true, grantData: { workspace: form.workspace } }
   * ```
   */
  readonly readConsentFields?: (
    input: ReadConsentFieldsInput,
  ) => MaybePromise<ConsentFieldsResult>
  /**
   * Last check before a grant is created, after the person approved. Only a
   * literal `true` (or `{ allow: true }`) continues; a refusal sends
   * `access_denied` to the client and revokes the upstream token.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * declare function hasSeat(subject: string): Promise<boolean>
   *
   * export const beforeGrant: McpAuthOptions["beforeGrant"] = async ({ subject }) =>
   *   (await hasSeat(subject)) ? true : { allow: false, reason: "no_seat" }
   * ```
   */
  readonly beforeGrant?: (
    context: BeforeGrantContext,
  ) => MaybePromise<PolicyDecision>
  /**
   * Called, and awaited, once a grant is stored and before the client gets
   * its code. If it throws, the grant and its code are deleted, the upstream
   * token is revoked and the client receives `server_error`, so a grant never
   * exists without your side effect.
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * declare function recordConnection(grantId: string, subject: string): Promise<void>
   *
   * export const afterGrant: McpAuthOptions["afterGrant"] = ({ grant }) =>
   *   recordConnection(grant.grantId, grant.subject)
   * ```
   */
  readonly afterGrant?: (context: AfterGrantContext) => Promise<void> | void
  /**
   * Checked before every token response, and before a refresh token is
   * used up, so a refusal never strands the client. Only a literal `true`
   * (or `{ allow: true }`) continues; a refusal answers `invalid_grant`, a
   * throw answers `temporarily_unavailable` (the refresh token stays usable).
   *
   * @example
   * ```ts
   * import type { McpAuthOptions } from "@gydr-ai/mcp-oauth"
   *
   * declare function accountActive(subject: string): Promise<boolean>
   *
   * export const beforeTokenIssue: McpAuthOptions["beforeTokenIssue"] = ({ grant }) =>
   *   accountActive(grant.subject)
   * ```
   */
  readonly beforeTokenIssue?: (
    context: BeforeTokenIssueContext,
  ) => MaybePromise<PolicyDecision>
  /**
   * Hashes of inline scripts a custom consent page may run, added to its
   * Content-Security-Policy `script-src`. Each must look like
   * `sha256-<base64 of 32 bytes>`. Default: none (no scripts run).
   */
  readonly scriptHashes?: readonly string[]
  /**
   * Seconds during which the same consent submission from the same browser
   * (a double click, a retried request) gets the same answer again instead
   * of an error. Needs the optional store methods `putConsentOutcome` and
   * `getConsentOutcome`; 0 to 60. Default: 10.
   */
  readonly consentReplaySeconds?: number
  /**
   * Allow `http://localhost`, `http://127.0.0.1` and `http://[::1]` for the
   * issuer and resource, for development. Default: `false`.
   */
  readonly allowInsecureLocalhost?: boolean
  /**
   * Clock in milliseconds since the epoch, for tests. A non-finite value
   * makes the request fail instead of disabling expiry checks.
   * Default: `Date.now`.
   */
  readonly now?: () => number
}

/**
 * {@link McpAuthOptions} with every default applied and checked.
 *
 * @internal
 */
export interface ResolvedOptions {
  /** Normalized issuer. */
  readonly issuer: string
  /** Origin of the issuer. */
  readonly issuerOrigin: string
  /** The protected resource. */
  readonly resource: string
  /** Absolute URL of the protected resource metadata. */
  readonly resourceMetadataUrl: string
  /** Paths serving protected resource metadata. */
  readonly resourceMetadataPaths: readonly string[]
  /** Paths serving authorization server metadata. */
  readonly authorizationServerMetadataPaths: readonly string[]
  /** Supported scopes. */
  readonly scopes: readonly string[]
  /** Scopes granted when none are requested. */
  readonly defaultScopes: readonly string[]
  /** Description per scope. */
  readonly scopeDescriptions: Readonly<Record<string, string>>
  /** Pre-registered clients by id. */
  readonly staticClients: ReadonlyMap<string, ClientRecord>
  /** RFC 9728 `resource_name`. */
  readonly resourceName?: string
  /** Identity provider. */
  readonly identityProvider: IdentityProvider
  /** Store. */
  readonly store: OAuthStore
  /** Sealer. */
  readonly sealer: SecretSealer
  /** Consent page renderer. */
  readonly renderConsentPage: (context: ConsentPageContext) => string
  /** Error page renderer. */
  readonly renderErrorPage: (context: ErrorPageContext) => string
  /** Access token lifetime in ms. */
  readonly accessTokenTtlMs: number
  /** Refresh token lifetime in ms. */
  readonly refreshTokenTtlMs: number
  /** Grant lifetime in ms. */
  readonly grantTtlMs: number
  /** Grant idle limit in ms; `0` when grants do not slide. */
  readonly grantIdleMs: number
  /** Grant types a client gets when it registers none. */
  readonly defaultGrantTypes: readonly (
    "authorization_code" | "refresh_token"
  )[]
  /** Authorization code lifetime in ms. */
  readonly codeTtlMs: number
  /** Sign-in plus consent time in ms. */
  readonly pendingTtlMs: number
  /** Metadata document cache lifetime in ms. */
  readonly clientMetadataCacheMs: number
  /** Metadata download back-off in ms. */
  readonly clientMetadataFailureMs: number
  /** Refresh retry window in ms. */
  readonly refreshReuseGraceMs: number
  /** Whether metadata-document clients are accepted. */
  readonly clientIdMetadataDocuments: boolean
  /** Whether registration is served. */
  readonly dynamicClientRegistration: boolean
  /** Endpoint paths. */
  readonly paths: Required<RoutePaths>
  /** Size and count limits. */
  readonly limits: Required<Limits>
  /** Custom metadata fetcher. */
  readonly fetchClientMetadata?: ClientMetadataFetcher
  /** Binding cookie name prefix. */
  readonly cookiePrefix: string
  /** Absolute callback URL. */
  readonly callbackUrl: string
  /** Rate-limit hook. */
  readonly rateLimit?: (key: string, scope: RateLimitScope) => Promise<boolean>
  /** Whether `X-Forwarded-For` is trusted. */
  readonly trustProxy: boolean
  /** Client IP resolver. */
  readonly getClientIp?: (request: Request) => string | undefined
  /** Event hook. */
  readonly onEvent?: McpAuthEventHandler
  /** Policy hook at `/authorize`. */
  readonly authorizeClient?: McpAuthOptions["authorizeClient"]
  /** Policy hook at `/register`. */
  readonly allowRegistration?: McpAuthOptions["allowRegistration"]
  /** Subject mapping hook. */
  readonly mapSubject?: McpAuthOptions["mapSubject"]
  /** Policy hook after sign-in. */
  readonly allowSubject?: McpAuthOptions["allowSubject"]
  /** Policy hook for metadata-document URLs. */
  readonly allowClientMetadataUrl?: McpAuthOptions["allowClientMetadataUrl"]
  /** Grant context hook. */
  readonly getGrantContext?: McpAuthOptions["getGrantContext"]
  /** Consent details hook. */
  readonly getConsentDetails?: McpAuthOptions["getConsentDetails"]
  /** Consent fields hook. */
  readonly readConsentFields?: McpAuthOptions["readConsentFields"]
  /** Pre-grant policy hook. */
  readonly beforeGrant?: McpAuthOptions["beforeGrant"]
  /** Post-grant hook. */
  readonly afterGrant?: McpAuthOptions["afterGrant"]
  /** Pre-token policy hook. */
  readonly beforeTokenIssue?: McpAuthOptions["beforeTokenIssue"]
  /** Allowed inline script hashes for the consent page. */
  readonly scriptHashes: readonly string[]
  /** Consent replay window in ms. */
  readonly consentReplayMs: number
  /** Clock. */
  readonly now: () => number
}
