import { ERROR_PAGES } from "../constants/error-pages.js"
import { clientIp } from "../helpers/client-ip.js"
import { frozenCopy } from "../helpers/freeze.js"
import { parseLocales } from "../helpers/locales.js"
import { permits } from "./policy.js"
import { html } from "../helpers/responses.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { ResolvedOptions } from "../interfaces/options.js"

/**
 * Build the context shared by every handler of one `createMcpAuth` instance.
 *
 * @param options - Checked options.
 * @returns The handler context.
 * @internal
 */
export function createContext(options: ResolvedOptions): HandlerContext {
  const emit: HandlerContext["emit"] = async (event) => {
    if (!options.onEvent) return

    try {
      await options.onEvent(event)
    } catch {
      // Logging trouble must not change an authorization outcome.
    }
  }

  return {
    options,
    cimd: { failures: new Map(), inflight: new Map() },
    emit,
    async allowed(request, scope) {
      if (!options.rateLimit) return true

      const limiter = options.rateLimit
      // Same rule as the policy hooks: only a literal `true` admits the
      // request; any other value, a rejection or a throw refuses it.
      const ok = await permits(() => limiter(clientIp(options, request), scope))

      if (!ok) await emit({ type: "request_throttled", scope })

      return ok
    },
    errorPage(request, reason, extra = {}) {
      const text = ERROR_PAGES[reason]
      const page = options.renderErrorPage(
        frozenCopy({
          status: text.status,
          reason,
          title: text.title,
          message: text.message,
          locales: parseLocales(request.headers.get("accept-language")),
          ...(extra.detail !== undefined ? { detail: extra.detail } : {}),
          ...(extra.policyReason !== undefined
            ? { policyReason: extra.policyReason }
            : {}),
        }),
      )

      return html(text.status, page, { setCookies: extra.setCookies ?? [] })
    },
  }
}
