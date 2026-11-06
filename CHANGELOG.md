# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [0.1.1](https://github.com/gydr-ai/mcp-oauth/compare/v0.1.0...v0.1.1) (2026-11-06)


### Bug Fixes

* linear-time trailing trims; escape dist-check names; allow-list dev-only licences ([#1](https://github.com/gydr-ai/mcp-oauth/issues/1)) ([3d6f286](https://github.com/gydr-ai/mcp-oauth/commit/3d6f2864f401766ea71158779eddb3640089da50))

## [Unreleased]

### 0.1.0 (initial release)

- OAuth 2.1 authorization server for remote MCP servers in front of any
  OpenID Connect identity provider: authorization code with PKCE S256,
  public clients, a consent step on every authorization, and no token
  passthrough.
- RFC 9728 protected resource metadata and RFC 8414 authorization server
  metadata, including the path-suffixed well-known forms.
- RFC 7591 Dynamic Client Registration with enforced `grant_types` and
  `scope`.
- Client ID Metadata Documents, downloaded through an injectable fetcher
  (default `@gydr-ai/safe-fetch`) with a deadline, size cap, back-off for
  failing URLs and shared concurrent downloads.
- Per-flow `__Host-` browser binding, checked before a flow is consumed, and
  a consent form with a one-time token and a strict Content-Security-Policy.
- Opaque access and refresh tokens stored only as SHA-256 hashes; refresh
  rotation with a configurable retry window and grant-wide revocation on
  replay; a repeated or mismatched authorization code ends its grant.
- RFC 7009 token revocation and `revokeGrant`; upstream refresh tokens are
  revoked at the identity provider whenever a flow or grant ends.
- `authenticate` resource-server guard with RFC 6750 / RFC 9728
  `WWW-Authenticate` challenges and audience checks.
- `getUpstreamAccessToken` with encrypted upstream tokens, in-memory caching
  and de-duplicated renewal per grant.
- Configurable lifetimes, size limits, paths, scopes, cookie prefix, page
  renderers, rate-limit hook and client-IP resolution.
- `createMemoryStore` (bounded, never evicts clients with live grants, idle
  expiry for dynamic clients), `createAesGcmSealer` (AES-256-GCM with key
  rotation) and `createOidcProvider` (discovery, PKCE, nonce, ID token
  verification with `jose`).
- Typed `onEvent` hook whose events never contain secrets.
- Extension points that can only tighten, enrich or observe:
  `authorizeClient`, `allowRegistration`, `allowSubject`,
  `allowClientMetadataUrl`, `mapSubject`, `getGrantContext`
  (`AuthResult.context`), pre-registered `clients` and `scopeDescriptions`.
- Minified ESM bundle with type declarations.
