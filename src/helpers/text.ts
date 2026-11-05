/**
 * Characters a display name must never contain: controls (Cc, which covers
 * C0, DEL and C1), every format character (Cf: soft hyphen, zero-width
 * space/joiners, LRM/RLM, bidirectional embeddings, overrides and isolates,
 * word joiner and invisible operators, BOM, ...), line and paragraph
 * separators (Zl, Zp), private-use (Co), lone surrogates (Cs) and
 * unassigned code points (Cn).
 */
const DISALLOWED = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{Cn}]/u

/**
 * True when `value` has a character that is invisible or changes how the
 * surrounding text is displayed. Such characters let an application name
 * pass itself off as another one on the consent page.
 *
 * @param value - Self-declared text to show a person, such as a client name or scope description.
 * @returns `true` when such a character is present.
 * @internal
 */
export function hasHiddenCharacters(value: string): boolean {
  return DISALLOWED.test(value)
}

const HTML_ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
}

/**
 * Escape a value for HTML text AND for a double- or single-quoted attribute.
 * Every interpolated value on a page goes through this.
 *
 * @param value - Text to escape.
 * @returns The escaped text.
 * @example
 * ```ts
 * import { type ConsentPageContext, escapeHtml } from "@gydr-ai/mcp-oauth"
 *
 * export function renderConsentPage(context: ConsentPageContext): string {
 *   const fields = Object.entries(context.hiddenFields)
 *     .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
 *     .join("")
 *
 *   return `<form method="post" action="${escapeHtml(context.formAction)}">${fields}
 * <button name="${escapeHtml(context.decisionField)}" value="approve">Allow</button>
 * <button name="${escapeHtml(context.decisionField)}" value="deny">Deny</button></form>`
 * }
 * ```
 */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char)
}

/**
 * True for an RFC 6749 § 3.3 scope-token: one or more of
 * %x21 / %x23-5B / %x5D-7E.
 *
 * @param value - One space-separated element of a `scope` value.
 * @returns `true` for a valid scope token.
 * @internal
 */
export function isScopeToken(value: string): boolean {
  if (value.length === 0) return false

  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i)

    if (
      code !== 0x21 &&
      !(code >= 0x23 && code <= 0x5b) &&
      !(code >= 0x5d && code <= 0x7e)
    ) {
      return false
    }
  }

  return true
}

/**
 * Remove every trailing occurrence of one character, in linear time. Used in
 * place of an end-anchored repeat pattern such as `/\/+$/`, whose regular
 * expression engine cost grows polynomially on long runs of the character.
 *
 * @param text - The string to trim, for example a URL path or host name.
 * @param char - The single character to strip from the end, such as `"/"`.
 * @returns `text` without any trailing `char`.
 */
export function trimTrailing(text: string, char: string): string {
  let end = text.length

  while (end > 0 && text[end - 1] === char) end -= 1

  return text.slice(0, end)
}
