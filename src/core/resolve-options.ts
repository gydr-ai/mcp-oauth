import {
  DEFAULT_CONSENT_REPLAY_SECONDS,
  DEFAULT_COOKIE_PREFIX,
  DEFAULT_LIFETIMES,
  DEFAULT_REFRESH_REUSE_GRACE_SECONDS,
  DEFAULT_SCOPES,
  LIFETIME_BOUNDS,
  MAX_CONSENT_REPLAY_SECONDS,
  MAX_REFRESH_REUSE_GRACE_SECONDS,
} from "../constants/defaults.js"
import {
  AUTHORIZATION_SERVER_METADATA_PATH,
  PROTECTED_RESOURCE_METADATA_PATH,
} from "../constants/protocol.js"
import { McpAuthConfigError } from "../errors/mcp-auth-config-error.js"
import { isScopeToken } from "../helpers/text.js"
import type { McpAuthOptions, ResolvedOptions } from "../interfaces/options.js"
import {
  resolveScopeDescriptions,
  resolveStaticClients,
} from "./resolve-clients.js"
import {
  parseServerUrl,
  resolveLimits,
  resolvePaths,
  seconds,
  trimPath,
} from "./resolve-parts.js"
import type {
  ConsentPageContext,
  ErrorPageContext,
} from "../interfaces/pages.js"
import { checkedClock } from "../helpers/time.js"

/** A CSP script hash: `sha256-` and the base64 of a 32-byte digest. */
const SCRIPT_HASH = /^sha256-[A-Za-z0-9+/]{43}=$/

/** A `__Host-` cookie name prefix made of cookie-token characters. */
const COOKIE_PREFIX = /^__Host-[A-Za-z0-9_.-]{0,40}$/

/**
 * Apply defaults to the options of `createMcpAuth` and check them.
 *
 * @param options - The options as given.
 * @param renderers - The built-in page renderers, used when none is given.
 * @param renderers.consent - Built-in consent page.
 * @param renderers.error - Built-in error page.
 * @returns The complete, checked options.
 * @throws {McpAuthConfigError} When any option is invalid.
 * @internal
 */
export function resolveOptions(
  options: McpAuthOptions,
  renderers: {
    readonly consent: (context: ConsentPageContext) => string
    readonly error: (context: ErrorPageContext) => string
  },
): ResolvedOptions {
  const insecure = options.allowInsecureLocalhost === true
  const issuerUrl = parseServerUrl("issuer", options.issuer, insecure)
  const issuerPath = trimPath(issuerUrl.pathname)
  const issuer = `${issuerUrl.origin}${issuerPath}`

  if (
    options.issuer !== issuer &&
    !(issuerPath === "" && options.issuer === `${issuer}/`)
  ) {
    throw new McpAuthConfigError(
      `issuer must be in normalized form, for example ${issuer}`,
    )
  }

  const resourceUrl = parseServerUrl("resource", options.resource, insecure)
  const resourcePath = trimPath(resourceUrl.pathname)
  const scopes = options.scopes ?? DEFAULT_SCOPES

  if (scopes.length === 0 || !scopes.every(isScopeToken)) {
    throw new McpAuthConfigError("scopes must be non-empty scope tokens")
  }

  const defaultScopes = options.defaultScopes ?? scopes

  if (
    defaultScopes.length === 0 ||
    !defaultScopes.every((scope) => scopes.includes(scope))
  ) {
    throw new McpAuthConfigError("defaultScopes must be a subset of scopes")
  }

  const graceSeconds =
    options.refreshReuseGraceSeconds ?? DEFAULT_REFRESH_REUSE_GRACE_SECONDS

  if (
    !Number.isInteger(graceSeconds) ||
    graceSeconds < 0 ||
    graceSeconds > MAX_REFRESH_REUSE_GRACE_SECONDS
  ) {
    throw new McpAuthConfigError(
      `refreshReuseGraceSeconds must be an integer from 0 to ${MAX_REFRESH_REUSE_GRACE_SECONDS}`,
    )
  }

  const lifetimes = options.lifetimes ?? {}
  const lifetime = (key: keyof typeof LIFETIME_BOUNDS): number =>
    seconds(
      key,
      lifetimes[key],
      DEFAULT_LIFETIMES[key],
      LIFETIME_BOUNDS[key].min,
      LIFETIME_BOUNDS[key].max,
    )
  const paths = resolvePaths(issuerPath, options.paths)
  const cookiePrefix = options.cookiePrefix ?? DEFAULT_COOKIE_PREFIX

  if (!COOKIE_PREFIX.test(cookiePrefix)) {
    throw new McpAuthConfigError(
      "cookiePrefix must start with __Host- and use only letters, digits, '.', '_' and '-'",
    )
  }

  const limits = resolveLimits(options.limits)
  const now = checkedClock(options.now ?? Date.now)
  const scriptHashes = [...(options.scriptHashes ?? [])]

  for (const hash of scriptHashes) {
    if (!SCRIPT_HASH.test(hash)) {
      throw new McpAuthConfigError(
        "scriptHashes entries must look like sha256-<base64 of 32 bytes>",
      )
    }
  }

  const replaySeconds =
    options.consentReplaySeconds ?? DEFAULT_CONSENT_REPLAY_SECONDS

  if (
    !Number.isInteger(replaySeconds) ||
    replaySeconds < 0 ||
    replaySeconds > MAX_CONSENT_REPLAY_SECONDS
  ) {
    throw new McpAuthConfigError(
      `consentReplaySeconds must be an integer from 0 to ${MAX_CONSENT_REPLAY_SECONDS}`,
    )
  }

  const prm = PROTECTED_RESOURCE_METADATA_PATH
  const asm = AUTHORIZATION_SERVER_METADATA_PATH
  const resourceMetadataPaths =
    resourcePath === "" ? [prm] : [`${prm}${resourcePath}`, prm]
  const authorizationServerMetadataPaths =
    issuerPath === "" ? [asm] : [`${asm}${issuerPath}`, asm]
  // An endpoint must not shadow a metadata document or the MCP endpoint
  // itself: `handle()` would answer it and the real route would be unreachable.
  const reserved = new Set([
    ...resourceMetadataPaths,
    ...authorizationServerMetadataPaths,
    resourceUrl.pathname,
    resourcePath === "" ? "/" : resourcePath,
  ])

  for (const [name, path] of Object.entries(paths)) {
    if (reserved.has(path)) {
      throw new McpAuthConfigError(
        `paths.${name} collides with a metadata path or the resource path`,
      )
    }
  }

  return {
    issuer,
    issuerOrigin: issuerUrl.origin,
    resource: options.resource,
    resourceMetadataUrl: `${resourceUrl.origin}${prm}${resourcePath}`,
    resourceMetadataPaths,
    authorizationServerMetadataPaths,
    scopes: [...scopes],
    defaultScopes: [...defaultScopes],
    identityProvider: options.identityProvider,
    store: options.store,
    sealer: options.sealer,
    renderConsentPage: options.renderConsentPage ?? renderers.consent,
    renderErrorPage: options.renderErrorPage ?? renderers.error,
    accessTokenTtlMs: lifetime("accessToken"),
    refreshTokenTtlMs: lifetime("refreshToken"),
    grantTtlMs: lifetime("grant"),
    codeTtlMs: lifetime("authorizationCode"),
    pendingTtlMs: lifetime("pendingAuthorization"),
    clientMetadataCacheMs: lifetime("clientMetadataCache"),
    clientMetadataFailureMs: lifetime("clientMetadataFailure"),
    limits,
    cookiePrefix,
    scriptHashes,
    consentReplayMs: replaySeconds * 1000,
    refreshReuseGraceMs: graceSeconds * 1000,
    clientIdMetadataDocuments: options.clientIdMetadataDocuments ?? true,
    dynamicClientRegistration: options.dynamicClientRegistration ?? true,
    paths,
    callbackUrl: `${issuerUrl.origin}${paths.callback}`,
    trustProxy: options.trustProxy ?? false,
    now,
    scopeDescriptions: resolveScopeDescriptions(
      scopes,
      options.scopeDescriptions,
    ),
    staticClients: resolveStaticClients(options.clients, scopes, limits, now),
    ...(options.resourceName !== undefined
      ? { resourceName: options.resourceName }
      : {}),
    ...(options.rateLimit ? { rateLimit: options.rateLimit } : {}),
    ...(options.getClientIp ? { getClientIp: options.getClientIp } : {}),
    ...(options.onEvent ? { onEvent: options.onEvent } : {}),
    ...(options.fetchClientMetadata
      ? { fetchClientMetadata: options.fetchClientMetadata }
      : {}),
    ...(options.authorizeClient
      ? { authorizeClient: options.authorizeClient }
      : {}),
    ...(options.allowRegistration
      ? { allowRegistration: options.allowRegistration }
      : {}),
    ...(options.mapSubject ? { mapSubject: options.mapSubject } : {}),
    ...(options.allowSubject ? { allowSubject: options.allowSubject } : {}),
    ...(options.allowClientMetadataUrl
      ? { allowClientMetadataUrl: options.allowClientMetadataUrl }
      : {}),
    ...(options.getGrantContext
      ? { getGrantContext: options.getGrantContext }
      : {}),
    ...(options.getConsentDetails
      ? { getConsentDetails: options.getConsentDetails }
      : {}),
    ...(options.readConsentFields
      ? { readConsentFields: options.readConsentFields }
      : {}),
    ...(options.beforeGrant ? { beforeGrant: options.beforeGrant } : {}),
    ...(options.afterGrant ? { afterGrant: options.afterGrant } : {}),
    ...(options.beforeTokenIssue
      ? { beforeTokenIssue: options.beforeTokenIssue }
      : {}),
  }
}
