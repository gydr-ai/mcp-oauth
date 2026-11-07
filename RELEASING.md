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
   environment, then **stages** that tarball through **Trusted Publishing**
   (OIDC). It installs and runs no project code, so no dependency can reach
   the publish token. npm attaches a provenance statement linking the
   package to that exact workflow run.
6. The staged version goes live only when a maintainer approves it on npm
   with 2FA (see "Approving a release").

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

npm only lets you trust a workflow for a package that already exists, and a
package only exists once a version is published. So the name is reserved
once with an inert placeholder, and every real version, the first included,
is staged by CI with provenance and approved by a maintainer. No npm token
is created at any point.

1. **Reserve the name** (from a clean checkout of `main`, logged in to npm
   with 2FA):

   ```bash
   node scripts/publish-placeholder.mjs
   ```

   This publishes `0.0.0-placeholder` (a README and a `package.json`, no
   code) under the `placeholder` dist-tag. It refuses to run if the package
   already exists.
   Run `npm logout` as soon as it finishes, so no session token stays in
   `~/.npmrc`.

2. **Trusted publisher**: on npmjs.com open the package → Settings →
   Trusted publishing → GitHub Actions, and enter:
   - Organization or user: `gydr-ai`
   - Repository: `mcp-oauth`
   - Workflow filename: `release.yml`
   - Environment name: `npm`
   - Allowed actions: leave **both unticked**. The publisher may then only
     _stage_ a version (`npm stage publish`); nothing goes live until a
     maintainer approves it with 2FA.
3. **Lock it down**: Settings → Publishing access → _Require two-factor
   authentication and disallow tokens_.
4. **First real release**: follow "Approving a release" below, then deprecate
   the placeholder:

   ```bash
   npm deprecate @gydr-ai/mcp-oauth@0.0.0-placeholder "Placeholder with no code; use @gydr-ai/mcp-oauth@latest"
   ```

5. **GitHub environment**: Settings → Environments → `npm` → add yourself
   (or the maintainers team) as a required reviewer. The setup script
   already limits deployments to `main`.
6. **Optional GitHub App** so CI also runs on the release pull request:
   create an org-owned GitHub App with _Contents_ and _Pull requests_
   read/write, install it on this repository, then set the repository
   variable `RELEASE_APP_ID` and secret `RELEASE_APP_PRIVATE_KEY`. Without
   it, the release pull request is opened with `GITHUB_TOKEN`, which GitHub
   does not let trigger other workflows.

## Approving a release

Every release needs two approvals, so a compromised GitHub account or
workflow alone can never put a version on npm:

1. **GitHub**: approve the `npm` environment deployment when the Release
   workflow asks. CI then _stages_ the version with provenance.
2. **npm**: approve the staged version on **npmjs.com**, not from a
   terminal: sign in → **Staged Packages** tab → open `@gydr-ai/mcp-oauth` → check the
   version and the provenance link to the `release.yml` run → **Approve**,
   then confirm with your security key. Reject a stage you did not expect.

   Approving in the browser leaves no credential on your machine. Never sign
   in to the npm CLI to approve, and never create an npm access token: the
   packages are set to "Require two-factor authentication and disallow
   tokens", so a token could not publish anyway, and one left in `~/.npmrc`
   is a credential waiting to leak. If you ever must use the CLI (for
   example `npm stage view` or `npm stage download` to inspect a stage), run
   `npm login --auth-type=web` just before, and `npm logout` straight after
   so the session token is ended on the server and removed from `~/.npmrc`.

## If publishing fails

The tag and the GitHub release exist as soon as the release pull request
merges, so a failed publish job does not need a new version. Fix the cause
on `main` first, then stage the same tag again: **Actions → Release → Run
workflow**, branch `main`, tag `vX.Y.Z`. The run rebuilds that tagged commit,
checks that its `package.json` version matches the tag, and asks for the
same two approvals. Check with `npm view @gydr-ai/mcp-oauth versions` that the version is
not already on npm before you start.

## Verifying a release

```bash
npm view @gydr-ai/mcp-oauth --json | jq '.dist.attestations'
npm audit signatures
```
