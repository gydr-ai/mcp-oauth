import { isScopeToken } from "./text.js"

/**
 * The scopes a `scope` parameter asks for, each listed once in the order
 * given. An absent parameter yields `fallback`. Returns `undefined` when the
 * value is longer than `maxLength`, empty, or names a scope outside
 * `permitted`.
 *
 * @param requested - The raw `scope` query value; `undefined` when absent.
 * @param permitted - Scopes this client may receive: its registered scopes, or all supported scopes.
 * @param fallback - Scopes granted when `requested` is absent; a subset of `permitted`.
 * @param maxLength - Longest `scope` value accepted, in characters (`limits.scopeLength`).
 * @returns The distinct requested scopes in request order (or `fallback` when none were requested), or `undefined` when the value is too long, empty, or names a scope outside `permitted`.
 * @internal
 */
export function resolveScopes(
  requested: string | undefined,
  permitted: readonly string[],
  fallback: readonly string[],
  maxLength: number,
): readonly string[] | undefined {
  if (requested === undefined) return fallback

  if (requested.length > maxLength) return undefined

  const asked = [...new Set(requested.split(" ").filter((s) => s.length > 0))]

  if (asked.length === 0) return undefined

  const allKnown = asked.every((s) => isScopeToken(s) && permitted.includes(s))

  return allKnown ? asked : undefined
}
