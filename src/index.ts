/**
 * `@gydr-ai/mcp-oauth`: an OAuth 2.1 authorization server and
 * resource-server guard for remote MCP servers, in front of any OpenID
 * Connect identity provider.
 *
 * @packageDocumentation
 */

export { createMcpAuth } from "./core/server.js"
export { createAesGcmSealer } from "./crypto/aes-gcm-sealer.js"
export { GrantInactiveError } from "./errors/grant-inactive-error.js"
export { IdentityProviderError } from "./errors/identity-provider-error.js"
export { McpAuthConfigError } from "./errors/mcp-auth-config-error.js"
export { SealerError } from "./errors/sealer-error.js"
export { UpstreamTokenError } from "./errors/upstream-token-error.js"
export { escapeHtml } from "./helpers/text.js"
export { createOidcProvider } from "./providers/oidc-provider.js"
export { createMemoryStore } from "./stores/memory-store.js"

export type { ErrorPageReason } from "./constants/error-pages.js"
export type {
  AfterGrantContext,
  BeforeGrantContext,
  BeforeTokenIssueContext,
  ConsentDetailsInput,
  ConsentFieldsResult,
  GrantSummary,
  HookClient,
  ReadConsentFieldsInput,
} from "./interfaces/consent.js"
export type {
  AuthFailure,
  AuthResult,
  AuthSuccess,
  BearerError,
  McpAuth,
} from "./interfaces/auth.js"
export type {
  GrantRevokeReason,
  McpAuthEvent,
  McpAuthEventHandler,
  RateLimitScope,
} from "./interfaces/events.js"
export type {
  AuthorizationUrlInput,
  ExchangeCodeInput,
  IdentityProvider,
  UpstreamLogin,
  UpstreamRenewalContext,
  UpstreamTokens,
} from "./interfaces/identity-provider.js"
export type { MemoryStoreOptions } from "./interfaces/memory-store.js"
export type { OidcProviderOptions } from "./interfaces/oidc.js"
export type {
  ClientMetadataFetcher,
  Lifetimes,
  Limits,
  McpAuthOptions,
  RoutePaths,
} from "./interfaces/options.js"
export type {
  ConsentPageContext,
  ErrorPageContext,
} from "./interfaces/pages.js"
export type {
  AllowRegistrationContext,
  AllowSubjectContext,
  AuthorizeClientContext,
  GrantContextInput,
  MappedSubject,
  MaybePromise,
  PolicyDecision,
  StaticClient,
  SubjectInput,
} from "./interfaces/policy.js"
export type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  ClientKind,
  ClientRecord,
  ConsentRequest,
  ConsumedAuthorizationCode,
  StoredAuthorizationCode,
  GrantRecord,
  GrantUpstreamUpdate,
  PendingAuthorization,
  RefreshTokenRecord,
  SupportedGrantType,
  UsedRefreshToken,
} from "./interfaces/records.js"
export type { AesGcmSealerOptions, SecretSealer } from "./interfaces/sealer.js"
export type { OAuthStore } from "./interfaces/store.js"
