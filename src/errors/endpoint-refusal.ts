/**
 * A request an OAuth endpoint turns down, converted into an RFC 6749 § 5.2
 * JSON error in a single place.
 *
 * @internal
 */
export class EndpointRefusal extends Error {
  /**
   * @param error - The OAuth error code.
   * @param description - Human-readable `error_description`.
   * @param status - HTTP status. Default: 400.
   * @param challenge - `WWW-Authenticate` value to send with the error.
   * @param detail - Why, for the `token_request_refused` event only; never sent to the caller.
   */
  constructor(
    readonly error: string,
    readonly description: string,
    readonly status: number = 400,
    readonly challenge?: string,
    readonly detail?: string,
  ) {
    super(description)
    this.name = "EndpointRefusal"
  }
}
