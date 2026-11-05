/**
 * A successful token endpoint response (RFC 6749 § 5.1).
 *
 * @internal
 */
export interface TokenResponse {
  /** The opaque access token. */
  readonly access_token: string
  /** Always `Bearer`. */
  readonly token_type: "Bearer"
  /** Seconds until the access token expires. */
  readonly expires_in: number
  /** Absent when the client did not register the refresh_token grant. */
  readonly refresh_token?: string
  /** Granted scopes, space-separated. */
  readonly scope: string
}
