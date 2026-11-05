/**
 * A Client ID Metadata Document was not accepted. Carries no document
 * content.
 *
 * @internal
 */
export class ClientMetadataError extends Error {
  /** Short machine-readable reason, reported in events. */
  readonly reason: string

  /**
   * @param reason - Short machine-readable reason.
   */
  constructor(reason: string) {
    super(`Client ID Metadata Document not accepted (${reason})`)
    this.name = "ClientMetadataError"
    this.reason = reason
  }
}
