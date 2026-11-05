# Security policy

`@gydr-ai/mcp-oauth` is security software. We treat every report seriously and will
credit you unless you prefer otherwise.

## Supported versions

Only the latest minor release line receives security fixes. Before 1.0.0,
that is the latest `0.x` release.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request.**

Report privately through GitHub:
[Report a vulnerability](https://github.com/gydr-ai/mcp-oauth/security/advisories/new).

Include what you can of:

- the affected version and Node.js version,
- a minimal reproduction or proof of concept,
- the impact you believe it has.

## What to expect

- Acknowledgement within 3 business days.
- An initial assessment, with a severity based on CVSS v4.0, within 10
  business days.
- A fix released as quickly as the severity warrants, followed by a GitHub
  Security Advisory and a CVE where one applies.

We ask that you keep the details private until the advisory is published,
and we will agree a disclosure date with you. We do not take legal action
against good-faith research that follows this policy.

## Supply chain

- Releases are published only from GitHub Actions through npm Trusted
  Publishing, with [npm provenance](https://docs.npmjs.com/generating-provenance-statements).
  You can verify a release with `npm audit signatures`.
- No long-lived npm token exists for this package.
- Every GitHub Action is pinned to a full commit SHA.
