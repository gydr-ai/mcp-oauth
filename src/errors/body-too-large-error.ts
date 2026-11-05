/**
 * A request body went past the size limit while it was being read.
 *
 * @internal
 */
export class BodyTooLargeError extends Error {
  /** Creates the error with a fixed message. */
  constructor() {
    super("Body exceeds the configured size limit")
    this.name = "BodyTooLargeError"
  }
}
