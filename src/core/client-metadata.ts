import { safeFetch } from "@gydr-ai/safe-fetch"

import { ClientMetadataError } from "../errors/client-metadata-error.js"
import {
  cleanClientName,
  parseClientScopes,
  parseGrantTypes,
} from "../helpers/client-fields.js"
import { isRecord, isStringArray } from "../helpers/guards.js"
import { isAcceptableRedirectUri } from "../helpers/redirect-uris.js"
import type {
  ClientMetadataFetcher,
  ResolvedOptions,
} from "../interfaces/options.js"
import type { ClientRecord } from "../interfaces/records.js"

/**
 * Turn a fetched document into a client record, or throw
 * {@link ClientMetadataError}. The document must name its own URL as
 * `client_id` and describe a public client. Redirect URIs this server would
 * never use (custom schemes, plain `http` off loopback) are left out; at
 * least one usable URI must remain.
 *
 * @param url - The `client_id` the document was downloaded from; the document's `client_id` must equal it exactly.
 * @param document - The parsed JSON body, of unknown shape.
 * @param now - Time of the download, in milliseconds since the epoch; stored as `createdAt`.
 * @param options - Supported scopes and size limits used to filter the document's values.
 * @returns A `metadata_document` client record with only usable redirect URIs, supported grant types and scopes, and a cleaned name.
 * @throws {ClientMetadataError} When the document is not an object, names another `client_id`, describes a confidential client, or has no usable grant type, response type, scope or redirect URI.
 * @internal
 */
export function validateClientMetadata(
  url: string,
  document: unknown,
  now: number,
  options: Pick<ResolvedOptions, "scopes" | "limits" | "defaultGrantTypes">,
): ClientRecord {
  if (!isRecord(document)) throw new ClientMetadataError("not_an_object")

  if (document.client_id !== url) {
    throw new ClientMetadataError("client_id_differs_from_url")
  }

  const methods = document.token_endpoint_auth_methods_supported

  // A client that names any way to authenticate other than `none` (singular,
  // or a plural list without `none`) is confidential.
  if (
    (document.token_endpoint_auth_method !== undefined &&
      document.token_endpoint_auth_method !== "none") ||
    (methods !== undefined &&
      (!isStringArray(methods) || !methods.includes("none"))) ||
    document.client_secret !== undefined
  ) {
    throw new ClientMetadataError("confidential_client")
  }

  const grantTypes = parseGrantTypes(
    document.grant_types,
    false,
    options.defaultGrantTypes,
  )

  if (grantTypes === undefined) {
    throw new ClientMetadataError("grant_types_unusable")
  }

  if (
    document.response_types !== undefined &&
    (!isStringArray(document.response_types) ||
      !document.response_types.includes("code"))
  ) {
    throw new ClientMetadataError("response_types_unusable")
  }

  const scopes = parseClientScopes(
    document.scope,
    options.scopes,
    false,
    options.limits.scopeLength,
  )

  if (scopes === undefined) throw new ClientMetadataError("scope_unusable")

  if (!isStringArray(document.redirect_uris)) {
    throw new ClientMetadataError("redirect_uris_absent")
  }

  const redirectUris = document.redirect_uris
    .filter((uri) => isAcceptableRedirectUri(uri, options.limits))
    .slice(0, options.limits.redirectUris)

  if (redirectUris.length === 0) {
    throw new ClientMetadataError("redirect_uris_unusable")
  }

  const clientName = cleanClientName(
    document.client_name,
    options.limits.clientNameLength,
  )

  return {
    clientId: url,
    redirectUris,
    kind: "metadata_document",
    createdAt: now,
    grantTypes,
    ...(scopes !== null ? { scopes } : {}),
    ...(clientName !== undefined ? { clientName } : {}),
  }
}

/**
 * The bundled fetcher: `@gydr-ai/safe-fetch`, redirects refused.
 *
 * @param options - Size limits supplying the download deadline and the largest accepted body.
 * @returns A fetcher with the configured deadline and size cap.
 */
function bundledFetcher(
  options: Pick<ResolvedOptions, "limits">,
): ClientMetadataFetcher {
  return (url, init) =>
    safeFetch(
      url,
      {
        method: "GET",
        headers: { Accept: "application/json" },
        redirect: "error",
        signal: init.signal,
      },
      {
        timeoutMs: options.limits.clientMetadataTimeoutMs,
        maxResponseBytes: options.limits.clientMetadataBytes,
        label: "client metadata",
      },
    )
}

/**
 * Resolve `work`, or reject as soon as `signal` aborts.
 *
 * @param work - Pending read or fetch to race against the deadline.
 * @param signal - Deadline signal created from `limits.clientMetadataTimeoutMs`.
 * @returns Whatever `work` resolves to.
 */
function beforeAbort<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new ClientMetadataError("timeout"))

  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(new ClientMetadataError("timeout"))
    }

    signal.addEventListener("abort", onAbort, { once: true })
    work.then(
      (value) => {
        signal.removeEventListener("abort", onAbort)
        resolve(value)
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort)
        reject(
          error instanceof Error
            ? error
            : new ClientMetadataError(failureReason(error)),
        )
      },
    )
  })
}

/**
 * Read at most `limit` bytes of a body as UTF-8, before the deadline.
 *
 * @param response - Response from the metadata fetcher with status 200.
 * @param limit - Largest body accepted, in bytes (`limits.clientMetadataBytes`); checked against `Content-Length` and while streaming.
 * @param signal - Deadline signal; reading stops with `timeout` when it fires.
 * @returns The body decoded as UTF-8.
 * @throws {ClientMetadataError} When the body is too large or the deadline passes.
 */
async function readLimited(
  response: Response,
  limit: number,
  signal: AbortSignal,
): Promise<string> {
  const declared = Number(response.headers.get("content-length"))

  if (Number.isFinite(declared) && declared > limit) {
    await response.body?.cancel().catch(() => {})
    throw new ClientMetadataError("too_large")
  }

  if (response.body === null) return ""

  const reader = response.body.getReader()
  const parts: Uint8Array[] = []
  let size = 0

  try {
    for (;;) {
      const chunk = await beforeAbort(reader.read(), signal)

      if (chunk.done) break

      const bytes: unknown = chunk.value

      if (!(bytes instanceof Uint8Array)) {
        throw new ClientMetadataError("not_bytes")
      }

      size += bytes.byteLength

      if (size > limit) throw new ClientMetadataError("too_large")

      parts.push(bytes)
    }
  } catch (error) {
    await reader.cancel().catch(() => {})
    throw error
  }

  return Buffer.concat(parts).toString("utf8")
}

/**
 * A short reason for a failed download, for events.
 *
 * @param error - What was thrown.
 * @returns The reason.
 * @internal
 */
export function failureReason(error: unknown): string {
  if (error instanceof ClientMetadataError) return error.reason

  if (!isRecord(error)) return "unreachable"

  if (typeof error.code === "string") return error.code

  return typeof error.reason === "string" ? error.reason : "unreachable"
}

/** A downloaded metadata document and how long it may be cached. */
export interface FetchedClient {
  /** The validated client. */
  readonly client: ClientRecord
  /**
   * The document's own `Cache-Control` lifetime in seconds: `max-age`, or
   * 0 for `no-store` / `no-cache`; `undefined` when it states none.
   */
  readonly maxAgeSeconds: number | undefined
}

/**
 * The cache lifetime a `Cache-Control` header states.
 *
 * @param header - The header value, if any.
 * @returns Seconds (0 for `no-store` / `no-cache`), or `undefined` when the
 *   header states no lifetime.
 * @internal
 */
export function cacheControlSeconds(header: string | null): number | undefined {
  if (header === null) return undefined

  let seconds: number | undefined

  for (const part of header.split(",")) {
    const [rawName = "", rawValue = ""] = part.split("=", 2)
    const name = rawName.trim().toLowerCase()

    switch (name) {
      case "no-store":
      case "no-cache":
        return 0
      case "max-age": {
        const value = rawValue.trim().replace(/^"(.*)"$/, "$1")

        seconds = /^\d{1,10}$/.test(value) ? Number(value) : 0
        break
      }
      default:
        break
    }
  }

  return seconds
}

/**
 * Download and validate one metadata document, without any caching. The
 * deadline, size cap, status check and document checks always apply, also
 * with a custom fetcher.
 *
 * @param url - A `client_id` already confirmed to be a metadata-document URL.
 * @param now - Time of the download, in milliseconds since the epoch.
 * @param options - Supported scopes, size limits, and the optional custom fetcher.
 * @returns The `metadata_document` client record and its stated cache lifetime.
 * @throws {ClientMetadataError} When the download fails, times out, is not status 200, is too large, is not JSON, or fails validation.
 * @internal
 */
export async function fetchClientMetadata(
  url: string,
  now: number,
  options: Pick<
    ResolvedOptions,
    "scopes" | "limits" | "fetchClientMetadata" | "defaultGrantTypes"
  >,
): Promise<FetchedClient> {
  const fetcher = options.fetchClientMetadata ?? bundledFetcher(options)
  const signal = AbortSignal.timeout(options.limits.clientMetadataTimeoutMs)
  let text: string
  let maxAgeSeconds: number | undefined

  try {
    const response = await beforeAbort(fetcher(url, { signal }), signal)

    if (response.status !== 200) {
      await response.body?.cancel().catch(() => {})
      throw new ClientMetadataError(`status_${response.status}`)
    }

    maxAgeSeconds = cacheControlSeconds(response.headers.get("cache-control"))
    text = await readLimited(
      response,
      options.limits.clientMetadataBytes,
      signal,
    )
  } catch (error) {
    throw error instanceof ClientMetadataError
      ? error
      : new ClientMetadataError(failureReason(error))
  }

  let document: unknown

  try {
    document = JSON.parse(text)
  } catch {
    throw new ClientMetadataError("invalid_json")
  }

  return {
    client: validateClientMetadata(url, document, now, options),
    maxAgeSeconds,
  }
}
