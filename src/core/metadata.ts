import type { ResolvedOptions } from "../interfaces/options.js"

/**
 * RFC 8414 authorization server metadata.
 *
 * @param options - Checked options; supplies the issuer, endpoint paths, scopes and enabled features.
 * @returns The RFC 8414 document, serialized as JSON by the caller.
 * @internal
 */
export function authorizationServerMetadata(
  options: ResolvedOptions,
): Record<string, unknown> {
  const at = (path: string) => `${options.issuerOrigin}${path}`

  return {
    issuer: options.issuer,
    authorization_endpoint: at(options.paths.authorize),
    token_endpoint: at(options.paths.token),
    ...(options.dynamicClientRegistration
      ? { registration_endpoint: at(options.paths.register) }
      : {}),
    revocation_endpoint: at(options.paths.revoke),
    scopes_supported: options.scopes,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: options.clientIdMetadataDocuments,
    authorization_response_iss_parameter_supported: true,
  }
}

/**
 * RFC 9728 protected resource metadata.
 *
 * @param options - Checked options; supplies the resource, issuer, scopes and resource name.
 * @returns The RFC 9728 document, serialized as JSON by the caller.
 * @internal
 */
export function protectedResourceMetadata(
  options: ResolvedOptions,
): Record<string, unknown> {
  return {
    resource: options.resource,
    authorization_servers: [options.issuer],
    scopes_supported: options.scopes,
    bearer_methods_supported: ["header"],
    ...(options.resourceName !== undefined
      ? { resource_name: options.resourceName }
      : {}),
  }
}
