import { cleanClientName } from "../helpers/client-fields.js"
import { frozenCopy } from "../helpers/freeze.js"
import { hasHiddenCharacters } from "../helpers/text.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { UpstreamLogin } from "../interfaces/identity-provider.js"
import type { MappedSubject } from "../interfaces/policy.js"
import type { ClientKind } from "../interfaces/records.js"
import { decide } from "./policy.js"

/** Longest subject accepted, from the identity provider or `mapSubject`. */
const SUBJECT_LENGTH_LIMIT = 512

/**
 * Whether a subject is safe to store and compare: a non-empty string of at
 * most 512 characters, without surrounding whitespace, already in Unicode
 * NFC form, and free of invisible or formatting characters. Two subjects
 * that look the same must be the same string.
 *
 * @param subject - A candidate subject, of unknown type.
 * @returns `true` when it may be stored.
 */
function isUsableSubject(subject: unknown): subject is string {
  return (
    typeof subject === "string" &&
    subject !== "" &&
    subject.length <= SUBJECT_LENGTH_LIMIT &&
    subject.trim() === subject &&
    subject.normalize("NFC") === subject &&
    !hasHiddenCharacters(subject)
  )
}

/**
 * Read what `mapSubject` returned. Each field is read exactly once, so an
 * object with getters cannot pass validation with one value and be stored
 * with another.
 *
 * @param value - The hook's result, of unknown shape.
 * @returns The subject and the raw display name, or `undefined` when the
 *   result is not an object.
 */
function readMapped(
  value: unknown,
): { subject: unknown; displayName: unknown } | undefined {
  if (typeof value !== "object" || value === null) return undefined

  const subject: unknown = Reflect.get(value, "subject")
  const displayName: unknown = Reflect.get(value, "displayName")

  return { subject, displayName }
}

/**
 * Decide who signed in: apply `mapSubject`, check the subject, clean the
 * display name, then ask `allowSubject`. Every step fails closed: an invalid
 * mapping, an unusable subject, a refusal or a thrown error means nobody is
 * signed in. Hooks receive deeply frozen copies.
 *
 * @param context - Context supplying the `mapSubject` and `allowSubject`
 *   hooks and `limits.clientNameLength` for display names.
 * @param login - What the identity provider reported, after its own checks.
 * @param client - The connecting client.
 * @param client.clientId - Its id.
 * @param client.clientName - Its display name.
 * @param client.kind - How it made itself known.
 * @returns The person to record, or a refusal with the reason
 *   `allowSubject` gave, if any.
 * @internal
 */
export async function resolvePerson(
  context: HandlerContext,
  login: UpstreamLogin,
  client: { clientId: string; clientName?: string; kind: ClientKind },
): Promise<
  | { readonly ok: true; readonly person: MappedSubject }
  | { readonly ok: false; readonly policyReason?: string }
> {
  const { mapSubject, allowSubject, limits } = context.options
  const claims = login.claims ?? {}
  let subject: unknown = login.subject
  let rawName: unknown = login.displayName

  if (mapSubject !== undefined) {
    let mapped: { subject: unknown; displayName: unknown } | undefined

    try {
      mapped = readMapped(
        await mapSubject(
          frozenCopy({
            subject: login.subject,
            claims,
            ...(login.displayName !== undefined
              ? { displayName: login.displayName }
              : {}),
          }),
        ),
      )
    } catch {
      return { ok: false }
    }

    if (mapped === undefined) return { ok: false }

    subject = mapped.subject
    rawName = mapped.displayName
  }

  if (!isUsableSubject(subject)) return { ok: false }

  // A display name is cosmetic: an unusable one is dropped, not fatal.
  const displayName =
    rawName === undefined
      ? undefined
      : cleanClientName(rawName, limits.clientNameLength)
  const person: MappedSubject =
    displayName === undefined ? { subject } : { subject, displayName }

  if (allowSubject !== undefined) {
    const outcome = await decide(() =>
      allowSubject(frozenCopy({ ...person, claims, client })),
    )

    if (!outcome.allowed) {
      return outcome.reason === undefined
        ? { ok: false }
        : { ok: false, policyReason: outcome.reason }
    }
  }

  return { ok: true, person }
}
