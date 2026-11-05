/** Most language tags taken from one `Accept-Language` header. */
const LOCALE_LIMIT = 10

/** A BCP 47-shaped language tag (letters, digits and hyphens). */
const TAG_PATTERN = /^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/

/**
 * The languages a browser prefers, from its `Accept-Language` header, most
 * preferred first. Malformed entries, `*` and `q=0` entries are dropped.
 *
 * @param header - The raw `Accept-Language` header value, or `null`.
 * @returns Up to 10 language tags, such as `["de-CH", "de", "en"]`.
 * @internal
 */
export function parseLocales(header: string | null): string[] {
  if (header === null) return []

  const ranked: { tag: string; q: number; order: number }[] = []

  for (const [order, part] of header.split(",").entries()) {
    const [rawTag = "", ...params] = part.trim().split(";")
    const tag = rawTag.trim()
    const qParam = params.map((p) => p.trim()).find((p) => p.startsWith("q="))
    const q = qParam === undefined ? 1 : Number(qParam.slice(2))

    if (TAG_PATTERN.test(tag) && Number.isFinite(q) && q > 0 && q <= 1) {
      ranked.push({ tag, q, order })
    }
  }

  ranked.sort((a, b) => b.q - a.q || a.order - b.order)

  return [...new Set(ranked.map((entry) => entry.tag))].slice(0, LOCALE_LIMIT)
}
