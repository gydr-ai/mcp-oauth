# Releasing

Releases are automatic. Nobody runs `npm publish` by hand after the first
release.

## How it works

1. Pull requests are squash-merged with a Conventional Commit title.
2. On every push to `main`, the **Release** workflow runs
   [release-please](https://github.com/googleapis/release-please), which opens
   or updates a pull request titled `chore(main): release x.y.z` containing
   the version bump and the generated `CHANGELOG.md` entry.
3. Merging that pull request creates the `vx.y.z` tag and GitHub release.
4. The `build` job checks out the tag, runs the full check and packs the
   tarball, with no publish permission at all.
5. The `publish` job waits for approval on the protected `npm`
   environment, then publishes that tarball through **Trusted Publishing**
   (OIDC). It installs and runs no project code, so no dependency can reach
   the publish token. npm attaches a provenance statement linking the
   package to that exact workflow run.

Before 1.0.0, a breaking change bumps the minor version and a feature bumps
the patch version (`bump-minor-pre-major`, `bump-patch-for-minor-pre-major`).

## Before the very first release

This package depends on `@gydr-ai/safe-fetch`, which is released from its
own repository. Until that package is on npm, `pnpm-workspace.yaml` links
it from `../safe-fetch`, and CI cannot install. So:

1. Release `@gydr-ai/safe-fetch` 0.1.0 first.
2. Here, delete the `@gydr-ai/safe-fetch` entry from `overrides` in
   `pnpm-workspace.yaml`, run `pnpm install` to rewrite `pnpm-lock.yaml`
   against the published version, run `pnpm check`, and commit.

## One-time setup

npm can only trust a workflow for a package that already exists, so the
first version is published once by a maintainer.

1. **First publish**: tag the initial commit `v0.1.0`, create its GitHub
   release, then from a clean checkout of that tag:
   ```bash
   pnpm install --frozen-lockfile && pnpm check
   npm publish --access public   # asks for your npm 2FA code
   ```
2. **Trusted publisher**: on npmjs.com open the package → Settings →
   Trusted publishing → GitHub Actions, and enter:
   - Organization or user: `gydr-ai`
   - Repository: `mcp-oauth`
   - Workflow filename: `release.yml`
   - Environment name: `npm`
   - Allowed actions: tick `npm publish`
3. **Lock it down**: Settings → Publishing access → _Require two-factor
   authentication and disallow tokens_.
4. **GitHub environment**: Settings → Environments → `npm` → add yourself
   (or the maintainers team) as a required reviewer. The setup script
   already limits deployments to `main`.
5. **Optional GitHub App** so CI also runs on the release pull request:
   create an org-owned GitHub App with _Contents_ and _Pull requests_
   read/write, install it on this repository, then set the repository
   variable `RELEASE_APP_ID` and secret `RELEASE_APP_PRIVATE_KEY`. Without
   it, the release pull request is opened with `GITHUB_TOKEN`, which GitHub
   does not let trigger other workflows.

## Verifying a release

```bash
npm view @gydr-ai/mcp-oauth --json | jq '.dist.attestations'
npm audit signatures
```
