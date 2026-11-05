import { EndpointRefusal } from "../errors/endpoint-refusal.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { GrantRecord } from "../interfaces/records.js"
import { grantSummary } from "./grant-summary.js"
import { judge } from "./policy.js"

/**
 * Run `beforeTokenIssue`, if set. It runs before a code or refresh token is
 * used up, so a refusal never strands the client.
 *
 * @param context - Context supplying the hook.
 * @param grant - The live grant tokens would be issued under.
 * @param grantType - Which token request this is.
 * @throws {EndpointRefusal} `invalid_grant` when the hook refuses, or
 *   `temporarily_unavailable` (503) when it throws.
 * @internal
 */
export async function requireTokenIssue(
  context: HandlerContext,
  grant: GrantRecord,
  grantType: "authorization_code" | "refresh_token",
): Promise<void> {
  const hook = context.options.beforeTokenIssue

  if (hook === undefined) return

  let verdict: unknown

  try {
    verdict = await hook(
      Object.freeze({ grant: grantSummary(grant), grantType }),
    )
  } catch {
    // A failing check is not a decision: the client may retry later with
    // the same, still unused, code or refresh token.
    throw new EndpointRefusal(
      "temporarily_unavailable",
      "Tokens cannot be issued right now; retry later",
      503,
    )
  }

  if (!judge(verdict).allowed) {
    throw new EndpointRefusal(
      "invalid_grant",
      "Tokens are not issued for this grant",
    )
  }
}
