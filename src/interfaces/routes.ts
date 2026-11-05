import type { GrantRevokeReason } from "./events.js"

/**
 * Ends a grant for the given reason.
 *
 * @internal
 */
export type RevokeGrant = (
  grantId: string,
  reason: GrantRevokeReason,
) => Promise<void>

/**
 * One route the server answers.
 *
 * @internal
 */
export interface RouteEntry {
  /** Accepted HTTP methods. */
  readonly methods: readonly string[]
  /** Handles the request. */
  readonly run: (request: Request) => Promise<Response>
  /** Browser-based clients call it cross-origin, without cookies. */
  readonly cors: boolean
}
