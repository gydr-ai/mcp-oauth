import type {
  ClientRecord,
  GrantRecord,
  SupportedGrantType,
} from "./records.js"

/**
 * A client the operator lists in the `clients` option.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export interface StaticClient {
  /** The `client_id`; must not be an `https` URL (those are metadata documents). */
  readonly clientId: string
  /** Redirect URIs, checked with the same rules as registration. */
  readonly redirectUris: readonly string[]
  /** Display name, checked for hidden characters. */
  readonly clientName?: string
  /** Grant types. Default: both `authorization_code` and `refresh_token`. */
  readonly grantTypes?: readonly SupportedGrantType[]
  /** Scopes the client may request, a subset of `scopes`. Default: any. */
  readonly scopes?: readonly string[]
}

/**
 * Input to the `authorizeClient` hook.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export interface AuthorizeClientContext {
  /** The client, already identified. */
  readonly client: ClientRecord
  /** The redirect URI, already matched against the client's registration. */
  readonly redirectUri: string
  /** The scopes that would be requested, already checked. */
  readonly scopes: readonly string[]
  /** The incoming `/authorize` request. */
  readonly request: Request
}

/**
 * Input to the `allowRegistration` hook.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export interface AllowRegistrationContext {
  /** The registration metadata as sent, after it passed validation. */
  readonly metadata: Readonly<Record<string, unknown>>
  /** The incoming `/register` request. */
  readonly request: Request
}

/**
 * The person as reported by the identity provider.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export interface SubjectInput {
  /** The provider's subject identifier. */
  readonly subject: string
  /** The provider's display name, if any. */
  readonly displayName?: string
  /** Claims the provider returned (for OpenID Connect, the ID token payload). */
  readonly claims: Readonly<Record<string, unknown>>
}

/**
 * Result of the `mapSubject` hook.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export interface MappedSubject {
  /** The subject to store on the grant; a non-empty string. */
  readonly subject: string
  /** Display name for the consent screen. */
  readonly displayName?: string
}

/**
 * Input to the `allowSubject` hook.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export interface AllowSubjectContext extends SubjectInput {
  /** The client the person is connecting. */
  readonly client: Pick<ClientRecord, "clientId" | "clientName" | "kind">
}

/**
 * What a policy hook returns: `true` (or `{ allow: true }`) to continue;
 * `false` or `{ allow: false, reason }` to refuse. `reason` is a short
 * machine-readable code (1–64 characters of `A-Z a-z 0-9 _ . : -`) passed to
 * the error page renderer as `policyReason`.
 *
 * @example
 * ```ts
 * import type { McpAuthOptions, PolicyDecision } from "@gydr-ai/mcp-oauth"
 *
 * export const allowSubject: McpAuthOptions["allowSubject"] = ({ claims }): PolicyDecision =>
 *   claims.email_verified === true ? true : { allow: false, reason: "email_unverified" }
 * ```
 */
export type PolicyDecision =
  boolean | { readonly allow: boolean; readonly reason?: string }

/**
 * A hook result that may be produced synchronously or asynchronously.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export type MaybePromise<T> = T | Promise<T>

/**
 * Input to the `getGrantContext` hook.
 *
 * @example
 * ```ts
 * import type {
 *   AllowRegistrationContext,
 *   AllowSubjectContext,
 *   AuthorizeClientContext,
 *   GrantContextInput,
 *   MappedSubject,
 *   MaybePromise,
 *   McpAuthOptions,
 *   StaticClient,
 *   SubjectInput,
 * } from "@gydr-ai/mcp-oauth"
 *
 * const desktop: StaticClient = {
 *   clientId: "team-desktop",
 *   redirectUris: ["http://127.0.0.1/callback"],
 *   grantTypes: ["authorization_code", "refresh_token"],
 * }
 *
 * export const policy: Partial<McpAuthOptions> = {
 *   clients: [desktop],
 *   authorizeClient: (context: AuthorizeClientContext) =>
 *     context.client.kind !== "dynamic" || !context.scopes.includes("mcp:write"),
 *   allowRegistration: (context: AllowRegistrationContext) =>
 *     typeof context.metadata.client_name === "string",
 *   mapSubject: (input: SubjectInput): MappedSubject => ({ subject: `idp|${input.subject}` }),
 *   allowSubject: (context: AllowSubjectContext): MaybePromise<boolean> =>
 *     context.claims.email_verified === true,
 *   getGrantContext: (grant: GrantContextInput) => ({ client: grant.clientId }),
 * }
 * ```
 */
export type GrantContextInput = Pick<
  GrantRecord,
  | "grantId"
  | "clientId"
  | "subject"
  | "scopes"
  | "resource"
  | "createdAt"
  | "data"
>
