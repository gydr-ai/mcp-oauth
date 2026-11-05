import { document } from "../helpers/html-document.js"
import { escapeHtml } from "../helpers/text.js"
import type {
  ConsentPageContext,
  ErrorPageContext,
} from "../interfaces/pages.js"

/**
 * The sentence telling the person who vouches for the application.
 *
 * @param context - Consent page data.
 * @returns HTML for the sentence.
 */
function provenance(context: ConsentPageContext): string {
  const unchecked = `<p class="note"><strong>Self-registered application.</strong> Nobody has checked the name above. Go on only if you just asked this application to connect.</p>`

  switch (context.clientKind) {
    case "static":
      return "<p>The operator of this service added this application.</p>"
    case "metadata_document":
      return context.clientHost === undefined || context.clientHost === ""
        ? unchecked
        : `<p>The description of this application is published at <strong>${escapeHtml(context.clientHost)}</strong>. The name above is the application's own claim.</p>`
    case "dynamic":
      return unchecked
  }
}

/**
 * The extra fields `readConsentFields` asked to correct, shown again with
 * their messages and the values the person sent, all escaped.
 *
 * @param context - Consent page data.
 * @returns HTML for the fields, or an empty string on a first showing.
 */
function correctionFields(context: ConsentPageContext): string {
  const errors = context.fieldErrors ?? {}
  const submitted = context.submitted ?? {}
  const names = [
    ...new Set([...Object.keys(errors), ...Object.keys(submitted)]),
  ]

  if (names.length === 0) return ""

  const items = names.map((name, index) => {
    const id = `field-${index}`
    const message = Object.hasOwn(errors, name) ? errors[name] : undefined
    const value = Object.hasOwn(submitted, name) ? submitted[name] : undefined
    const note =
      message === undefined
        ? ""
        : `<span class="note" id="${id}-error">${escapeHtml(message)}</span>`
    const described =
      message === undefined
        ? ""
        : ` aria-invalid="true" aria-describedby="${id}-error"`

    return `<p><label for="${id}">${escapeHtml(name)}</label>
<input type="text" id="${id}" name="${escapeHtml(name)}" value="${escapeHtml(value ?? "")}"${described}>
${note}</p>`
  })

  return `<section class="facts" role="alert">${items.join("\n")}</section>`
}

/**
 * The consent page used unless `renderConsentPage` is set.
 *
 * @param context - Consent page data.
 * @returns The HTML document.
 * @internal
 */
export function defaultConsentPage(context: ConsentPageContext): string {
  const title = context.clientName ?? "An application without a name"
  const delivery = context.redirectIsLoopback
    ? `a program running on this device (${escapeHtml(context.redirectHost)})`
    : escapeHtml(context.redirectHost)
  const account =
    context.subjectDisplayName === undefined
      ? ""
      : `<p>You are signed in as <strong>${escapeHtml(context.subjectDisplayName)}</strong>.</p>`
  const scopeItems = context.scopes
    .map((scope) => {
      // Own properties only: a scope named like a prototype member
      // (`constructor`, `toString`) has no description unless configured.
      const description = Object.hasOwn(context.scopeDescriptions, scope)
        ? context.scopeDescriptions[scope]
        : undefined
      const detail =
        description === undefined ? "" : ` — ${escapeHtml(description)}`

      return `<li><code>${escapeHtml(scope)}</code>${detail}</li>`
    })
    .join("")
  const fields = Object.entries(context.hiddenFields)
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`,
    )
    .join("\n")
  const decision = escapeHtml(context.decisionField)
  const corrections = correctionFields(context)

  return document(
    "Connect application",
    `<h1>Connect <strong>${escapeHtml(title)}</strong>?</h1>
${account}
${provenance(context)}
<section class="facts">
<p><span>Permissions</span></p><ul>${scopeItems}</ul>
<p><span>Service</span> ${escapeHtml(context.resource)}</p>
<p><span>Result goes to</span> ${delivery}</p>
<p><span>Application id</span> <code>${escapeHtml(context.clientId)}</code></p>
</section>
<p>Connect only applications you recognise. The connection can be removed again at any time.</p>
<form method="post" action="${escapeHtml(context.formAction)}">
${fields}
${corrections}
<p class="choices">
<button type="submit" name="${decision}" value="approve" class="go">Connect</button>
<button type="submit" name="${decision}" value="deny">Cancel</button>
</p>
</form>`,
  )
}

/**
 * The error page used unless `renderErrorPage` is set.
 *
 * @param context - Error page data.
 * @returns The HTML document.
 * @internal
 */
export function defaultErrorPage(context: ErrorPageContext): string {
  return document(
    context.title,
    `<h1>${escapeHtml(context.title)}</h1>
<p>${escapeHtml(context.message)}</p>${
      context.detail === undefined
        ? ""
        : `\n<p class="note">${escapeHtml(context.detail)}</p>`
    }`,
  )
}
