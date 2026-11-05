import type { ErrorPageReason } from "../constants/error-pages.js"
import type { McpAuthEvent, RateLimitScope } from "./events.js"
import type { ResolvedOptions } from "./options.js"
import type { ClientRecord } from "./records.js"

/**
 * Shared state and helpers handed to every route handler.
 *
 * @internal
 */
export interface HandlerContext {
  /** The checked options. */
  readonly options: ResolvedOptions
  /** Per-instance Client ID Metadata Document download state. */
  readonly cimd: {
    /** URL to the time until which a failed download is not retried. */
    readonly failures: Map<string, number>
    /** URL to the download in progress. */
    readonly inflight: Map<string, Promise<ClientRecord | undefined>>
  }
  /** Deliver an event to `onEvent`; never rejects. */
  emit(event: McpAuthEvent): Promise<void>
  /** Whether the request may proceed; a failing limiter refuses. */
  allowed(request: Request, scope: RateLimitScope): Promise<boolean>
  /** Build an error page response for a reason code. */
  errorPage(
    request: Request,
    reason: ErrorPageReason,
    extra?: {
      readonly detail?: string
      readonly policyReason?: string
      readonly setCookies?: readonly string[]
    },
  ): Response
}
