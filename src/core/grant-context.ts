import { jsonCopy } from "../helpers/json.js"
import { frozenCopy } from "../helpers/freeze.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { GrantRecord } from "../interfaces/records.js"

/**
 * Ask `getGrantContext` for the data to expose on `AuthResult.context`.
 *
 * The hook sees a copy of the grant's public fields and its result is
 * returned as a fresh JSON copy, so it can neither change the grant nor leak
 * live objects between requests. A result that cannot be serialized, or is
 * larger than `limits.grantContextBytes`, is an integration error.
 *
 * @param context - Context supplying the `getGrantContext` hook and `limits.grantContextBytes`.
 * @param grant - The grant behind the token.
 * @returns A JSON-safe copy of the hook's result, or `undefined` without a hook.
 * @throws {TypeError} When the result is not JSON-serializable or too large.
 * @internal
 */
export async function grantContextFor(
  context: HandlerContext,
  grant: GrantRecord,
): Promise<unknown> {
  const hook = context.options.getGrantContext

  if (hook === undefined) return undefined

  const result = await hook(
    frozenCopy({
      grantId: grant.grantId,
      clientId: grant.clientId,
      subject: grant.subject,
      scopes: [...grant.scopes],
      resource: grant.resource,
      createdAt: grant.createdAt,
      ...(grant.data !== undefined ? { data: grant.data } : {}),
    }),
  )

  return jsonCopy(
    result,
    context.options.limits.grantContextBytes,
    "getGrantContext",
  )
}
