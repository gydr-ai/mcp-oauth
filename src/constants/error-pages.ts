/**
 * Stable reason codes for error pages. A custom `renderErrorPage` can switch
 * on them to show its own wording or language.
 *
 * @example
 * ```ts
 * import type { ErrorPageReason } from "@gydr-ai/mcp-oauth"
 *
 * export function heading(reason: ErrorPageReason): string {
 *   switch (reason) {
 *     case "access_denied":
 *       return "Access not granted"
 *     case "rate_limited":
 *       return "Slow down"
 *     default:
 *       return "Something went wrong"
 *   }
 * }
 * ```
 */
export type ErrorPageReason =
  | "rate_limited"
  | "repeated_parameter"
  | "client_unknown"
  | "redirect_uri_not_registered"
  | "invalid_request"
  | "unsupported_response_type"
  | "invalid_target"
  | "invalid_scope"
  | "consent_required"
  | "access_denied"
  | "flow_ended"
  | "malformed_response"
  | "browser_mismatch"
  | "sign_in_not_confirmed"
  | "subject_not_permitted"
  | "consent_unavailable"
  | "unsupported_submission"
  | "server_error"

/** Status, title and message of one built-in error page. */
interface ErrorPageText {
  /** HTTP status. */
  readonly status: number
  /** Heading. */
  readonly title: string
  /** Explanation for the person. */
  readonly message: string
}

/**
 * Built-in status, title and message for every error page reason.
 *
 * @internal
 */
export const ERROR_PAGES: Readonly<Record<ErrorPageReason, ErrorPageText>> = {
  rate_limited: {
    status: 429,
    title: "Slow down",
    message:
      "An unusual number of requests came from your network just now. Please wait a little, then start again from your application.",
  },
  repeated_parameter: {
    status: 400,
    title: "Malformed link",
    message:
      "The link that opened this page names the same setting more than once, so it cannot be trusted.",
  },
  client_unknown: {
    status: 400,
    title: "Application not recognised",
    message:
      "The application that opened this page is not known to this server. Try connecting again from the application.",
  },
  redirect_uri_not_registered: {
    status: 400,
    title: "Unexpected return address",
    message:
      "The application asked for the result to go somewhere other than the return addresses it registered, so nothing was sent.",
  },
  invalid_request: {
    status: 400,
    title: "Incomplete request",
    message:
      "The application sent a request this server cannot accept. Please try connecting again from the application.",
  },
  unsupported_response_type: {
    status: 400,
    title: "Unsupported request",
    message:
      "The application asked for a kind of sign-in this server does not offer.",
  },
  invalid_target: {
    status: 400,
    title: "Wrong service",
    message:
      "The application asked for access to a service this server does not protect.",
  },
  invalid_scope: {
    status: 400,
    title: "Unavailable permissions",
    message:
      "The application asked for permissions that are not available to it.",
  },
  consent_required: {
    status: 400,
    title: "Approval needed",
    message:
      "This server always asks you before granting access, but the application asked to skip that step.",
  },
  access_denied: {
    status: 403,
    title: "Not permitted",
    message: "This application may not connect to this service.",
  },
  flow_ended: {
    status: 400,
    title: "This sign-in has ended",
    message:
      "The sign-in you returned from is no longer open, either because it took too long or because it was already completed. Please connect again from your application.",
  },
  malformed_response: {
    status: 400,
    title: "Malformed response",
    message:
      "The identity provider's response could not be used to finish signing in.",
  },
  browser_mismatch: {
    status: 400,
    title: "Different browser",
    message:
      "This sign-in has to finish in the browser where it began. Open your application on this device and connect again.",
  },
  sign_in_not_confirmed: {
    status: 400,
    title: "Sign-in not confirmed",
    message:
      "Your identity provider did not confirm who you are. Please connect again from your application.",
  },
  subject_not_permitted: {
    status: 403,
    title: "Access not permitted",
    message: "The account you signed in with may not connect this application.",
  },
  consent_unavailable: {
    status: 400,
    title: "Nothing to approve",
    message:
      "There is no open request to approve here. It may have been answered already, taken too long, or been opened in another browser. Please connect again from your application.",
  },
  unsupported_submission: {
    status: 415,
    title: "Unexpected submission",
    message: "Your answer must be sent with the form on the previous page.",
  },
  server_error: {
    status: 500,
    title: "Unexpected problem",
    message:
      "Something on this server stopped the request from finishing. Please start again from your application.",
  },
}
