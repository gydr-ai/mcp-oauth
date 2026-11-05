import { trimTrailing } from "../helpers/text.js"
import { CLIENT_ID_LENGTH_LIMIT } from "../constants/defaults.js"
import { isMetadataDocumentClientId } from "../helpers/client-fields.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { ClientRecord } from "../interfaces/records.js"
import {
  failureReason,
  fetchClientMetadata,
  type FetchedClient,
} from "./client-metadata.js"
import { permits } from "./policy.js"

/**
 * The host of a URL, for events.
 *
 * @param url - Any URL.
 * @returns Its host, or an empty string.
 */
function hostOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return ""
  }
}

/**
 * A URL reduced to what identifies a server: scheme, host without a
 * trailing dot, port (the parser drops a default one) and path without
 * trailing slashes. Query and fragment are ignored.
 *
 * @param value - An absolute URL.
 * @returns The reduced form, or `undefined` when it does not parse.
 */
function serverIdentity(value: string): string | undefined {
  let url: URL

  try {
    url = new URL(value)
  } catch {
    return undefined
  }

  const host = trimTrailing(url.hostname, ".")
  const path = trimTrailing(url.pathname, "/")

  return `${url.protocol}//${host}:${url.port}${path}`
}

/**
 * Whether a URL names the issuer itself, compared after parsing.
 *
 * @param url - A metadata-document `client_id`.
 * @param issuer - The configured issuer.
 * @returns `true` when both identify the same server URL.
 * @internal
 */
export function isIssuerUrl(url: string, issuer: string): boolean {
  const given = serverIdentity(url)

  return given !== undefined && given === serverIdentity(issuer)
}

/**
 * Find the client behind a `client_id`. Opaque ids are looked up among the
 * pre-registered clients, then in the store; a URL id is checked against
 * `allowClientMetadataUrl`, then served from the metadata cache or
 * downloaded.
 *
 * @param context - Context supplying the store, pre-registered clients, metadata policy hook and the per-instance download state.
 * @param clientId - The `client_id` as sent.
 * @returns The client, or `undefined` when it is unknown or unusable.
 * @internal
 */
export async function resolveClient(
  context: HandlerContext,
  clientId: string,
): Promise<ClientRecord | undefined> {
  const { options } = context

  if (clientId.length > CLIENT_ID_LENGTH_LIMIT) return undefined

  if (!isMetadataDocumentClientId(clientId)) {
    const listed = options.staticClients.get(clientId)

    if (listed !== undefined) return listed

    const stored = await options.store.getClient(clientId)

    // Only a real download may produce a metadata-document client.
    return stored?.kind === "metadata_document" ? undefined : stored
  }

  if (!options.clientIdMetadataDocuments) return undefined

  // The authorization server's own URL can never be a client of it
  // (CIMD-03 security considerations).
  if (isIssuerUrl(clientId, options.issuer)) {
    await context.emit({
      type: "client_metadata_refused",
      host: hostOf(clientId),
      reason: "client_id_is_issuer",
    })

    return undefined
  }

  const allow = options.allowClientMetadataUrl

  if (allow !== undefined && !(await permits(() => allow(clientId)))) {
    await context.emit({
      type: "client_metadata_refused",
      host: hostOf(clientId),
      reason: "not_allowed_by_policy",
    })

    return undefined
  }

  const cached = await options.store.getCachedClientMetadata(clientId)

  if (cached?.clientId === clientId) return cached

  const { failures, inflight } = context.cimd
  const retryAfter = failures.get(clientId)

  // A URL that recently failed is not contacted again until its back-off
  // ends: repeated authorization attempts cannot multiply outbound requests.
  if (retryAfter !== undefined) {
    if (retryAfter > options.now()) return undefined

    failures.delete(clientId)
  }

  // Simultaneous requests for the same URL wait on one download.
  const pending = inflight.get(clientId)

  if (pending !== undefined) return pending

  const download = downloadAndRemember(context, clientId).finally(() => {
    inflight.delete(clientId)
  })

  inflight.set(clientId, download)

  return download
}

/**
 * Download a metadata document, cache it on success and remember a failure.
 *
 * @param context - Context supplying the clock, cache lifetime, fetcher and event hook.
 * @param clientId - The document URL.
 * @returns The client, or `undefined` on failure.
 */
async function downloadAndRemember(
  context: HandlerContext,
  clientId: string,
): Promise<ClientRecord | undefined> {
  const { options } = context
  const startedAt = options.now()
  let fetched: FetchedClient

  try {
    fetched = await fetchClientMetadata(clientId, startedAt, options)
  } catch (error) {
    rememberFailure(context, clientId)
    await context.emit({
      type: "client_metadata_refused",
      host: hostOf(clientId),
      reason: failureReason(error),
    })

    return undefined
  }

  // The document's own `Cache-Control` is honoured, never beyond the
  // configured lifetime (CIMD-03 § 4.2).
  const stated = fetched.maxAgeSeconds
  const cacheMs =
    stated === undefined
      ? options.clientMetadataCacheMs
      : Math.min(stated * 1000, options.clientMetadataCacheMs)

  if (cacheMs > 0) {
    await options.store.putCachedClientMetadata(
      clientId,
      fetched.client,
      startedAt + cacheMs,
    )
  }

  return fetched.client
}

/**
 * Remember that a URL failed, evicting the oldest entry when the list is full.
 *
 * @param context - Context holding the per-instance failure map and its configured size and back-off.
 * @param clientId - The document URL.
 */
function rememberFailure(context: HandlerContext, clientId: string): void {
  const { options } = context
  const { failures } = context.cimd

  if (options.clientMetadataFailureMs === 0) return

  failures.delete(clientId)

  while (failures.size >= options.limits.clientMetadataFailures) {
    const oldest = failures.keys().next()

    if (oldest.done === true) break

    failures.delete(oldest.value)
  }

  failures.set(clientId, options.now() + options.clientMetadataFailureMs)
}
