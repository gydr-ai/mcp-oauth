import { isRecord } from "../helpers/guards.js"
import type { MaybePromise, PolicyDecision } from "../interfaces/policy.js"

/** A refusal reason: short, machine-readable, safe to pass to a renderer. */
const REASON_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/

/** The outcome of a policy hook, after validation. */
export interface PolicyOutcome {
  /** Whether the request may continue. */
  readonly allowed: boolean
  /** The hook's reason for a refusal, when it gave a valid one. */
  readonly reason?: string
}

/**
 * Run a policy hook that may only refuse.
 *
 * Only a literal `true`, or an object whose `allow` is the literal `true`,
 * lets the request continue. `false`, any other value, a rejection or a
 * throw refuses, so a broken hook can never open a door. A refusal may carry
 * a `reason` of 1–64 characters from `A-Z a-z 0-9 _ . : -`; any other reason
 * is dropped (the request is still refused).
 *
 * @param check - Calls the hook; may return a value or a promise.
 * @returns Whether the request may continue, and a valid refusal reason.
 * @internal
 */
export async function decide(
  check: () => MaybePromise<PolicyDecision>,
): Promise<PolicyOutcome> {
  let verdict: unknown

  try {
    // Hooks are written in plain JavaScript too: trust no declared type.
    verdict = await check()
  } catch {
    return { allowed: false }
  }

  return judge(verdict)
}

/**
 * Read a policy verdict that has already been obtained (see {@link decide}).
 *
 * @param verdict - Whatever the hook returned.
 * @returns Whether the request may continue, and a valid refusal reason.
 * @internal
 */
export function judge(verdict: unknown): PolicyOutcome {
  if (verdict === true) return { allowed: true }

  if (!isRecord(verdict)) return { allowed: false }

  if (verdict.allow === true) return { allowed: true }

  const reason = verdict.reason

  return typeof reason === "string" && REASON_PATTERN.test(reason)
    ? { allowed: false, reason }
    : { allowed: false }
}

/**
 * Run a policy hook and report only whether the request may continue.
 *
 * @param check - Calls the hook; may return a value or a promise.
 * @returns `true` only for an allowing verdict (see {@link decide}).
 * @internal
 */
export async function permits(
  check: () => MaybePromise<PolicyDecision>,
): Promise<boolean> {
  return (await decide(check)).allowed
}
