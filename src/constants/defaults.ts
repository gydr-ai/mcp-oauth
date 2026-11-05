/**
 * Default lifetimes in seconds, applied when `lifetimes` omits a value.
 *
 * @internal
 */
export const DEFAULT_LIFETIMES = {
  accessToken: 1800,
  refreshToken: 1_209_600,
  grant: 7_776_000,
  authorizationCode: 60,
  pendingAuthorization: 900,
  clientMetadataCache: 1800,
  clientMetadataFailure: 60,
} as const

/**
 * Smallest and largest configurable lifetimes, in seconds. The caps keep a
 * typo from creating codes or sign-in windows that live for days, or tokens
 * that never expire in practice.
 *
 * @internal
 */
export const LIFETIME_BOUNDS = {
  accessToken: { min: 1, max: 86_400 },
  refreshToken: { min: 1, max: 34_560_000 },
  grant: { min: 1, max: 34_560_000 },
  authorizationCode: { min: 1, max: 600 },
  pendingAuthorization: { min: 1, max: 3600 },
  clientMetadataCache: { min: 0, max: 86_400 },
  clientMetadataFailure: { min: 0, max: 3600 },
} as const

/**
 * Default size and count limits, applied when `limits` omits a value.
 *
 * @internal
 */
export const DEFAULT_LIMITS = {
  clientNameLength: 128,
  redirectUris: 8,
  redirectUriLength: 2048,
  stateLength: 2048,
  scopeLength: 1024,
  registrationBytes: 16 * 1024,
  formBytes: 32 * 1024,
  clientMetadataBytes: 5 * 1024,
  clientMetadataTimeoutMs: 4000,
  clientMetadataFailures: 10_000,
  grantContextBytes: 4096,
  consentDetailsBytes: 8192,
  grantDataBytes: 4096,
} as const

/**
 * Scopes offered when `scopes` is not set.
 *
 * @internal
 */
export const DEFAULT_SCOPES: readonly string[] = ["mcp"]

/**
 * Retry window for a just-used refresh token, in seconds.
 *
 * @internal
 */
export const DEFAULT_REFRESH_REUSE_GRACE_SECONDS = 10

/**
 * Longest refresh retry window that may be configured, in seconds.
 *
 * @internal
 */
export const MAX_REFRESH_REUSE_GRACE_SECONDS = 300

/**
 * Default name prefix of the browser-binding cookie.
 *
 * @internal
 */
export const DEFAULT_COOKIE_PREFIX = "__Host-mcp-auth-"

/**
 * Default capacity of each memory-store collection.
 *
 * @internal
 */
export const DEFAULT_MEMORY_STORE_ENTRIES = 100_000

/**
 * Default idle lifetime of a grant-less dynamic client in the memory store, in seconds (28 days).
 *
 * @internal
 */
export const DEFAULT_DYNAMIC_CLIENT_IDLE_SECONDS = 2_419_200

/**
 * Upstream access tokens are renewed this long before they expire.
 *
 * @internal
 */
export const UPSTREAM_EXPIRY_SKEW_MS = 60_000

/**
 * Most grants whose upstream access token is cached in memory.
 *
 * @internal
 */
export const UPSTREAM_CACHE_GRANTS = 10_000

/**
 * Upstream access tokens are treated as expiring within a day at most.
 *
 * @internal
 */
export const UPSTREAM_LIFETIME_CEILING_SECONDS = 86_400

/**
 * `client_id` values longer than this are never looked up.
 *
 * @internal
 */
export const CLIENT_ID_LENGTH_LIMIT = 2048

/**
 * Cache lifetime of metadata responses, in seconds.
 *
 * @internal
 */
export const METADATA_MAX_AGE_SECONDS = 600

/**
 * Default seconds during which a repeated consent submission gets the same
 * answer.
 *
 * @internal
 */
export const DEFAULT_CONSENT_REPLAY_SECONDS = 10

/**
 * Longest configurable consent replay window, in seconds.
 *
 * @internal
 */
export const MAX_CONSENT_REPLAY_SECONDS = 60
