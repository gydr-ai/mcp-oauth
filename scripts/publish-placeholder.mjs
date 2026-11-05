// Publishes an inert placeholder version so the package name exists on npm.
//
// npm only lets you trust a GitHub workflow (trusted publishing over OIDC)
// for a package that already exists. Run this ONCE, by hand, before the first
// release: it publishes `0.0.0-placeholder` (a README and a package.json, no
// code) under your own npm login and 2FA, so no token is ever created. Every
// real version is then published by the Release workflow, with provenance.
//
// Usage: node scripts/publish-placeholder.mjs

import { spawnSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const PLACEHOLDER_VERSION = "0.0.0-placeholder"
const PLACEHOLDER_TAG = "placeholder"

const manifest = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
)
const { name, license, repository, homepage } = manifest

/**
 * Run an npm command, inheriting the terminal so npm can ask for the 2FA code.
 *
 * @param {string[]} args - Arguments after `npm`.
 * @param {{ cwd?: string, quiet?: boolean }} [options] - Working directory,
 *   and whether to capture output instead of showing it.
 * @returns {import("node:child_process").SpawnSyncReturns<string>} The result.
 */
function npm(args, options = {}) {
  return spawnSync("npm", args, {
    cwd: options.cwd,
    encoding: "utf8",
    stdio: options.quiet === true ? "pipe" : "inherit",
  })
}

const existing = npm(["view", name, "name"], { quiet: true })

if (existing.status === 0 && existing.stdout.trim() === name) {
  console.error(`${name} already exists on npm; no placeholder is needed.`)
  process.exit(1)
}

const directory = mkdtempSync(join(tmpdir(), "npm-placeholder-"))

try {
  writeFileSync(
    join(directory, "package.json"),
    `${JSON.stringify(
      {
        name,
        version: PLACEHOLDER_VERSION,
        description:
          "Placeholder that reserves this name for trusted publishing. Install a real release instead.",
        license,
        repository,
        homepage,
        publishConfig: { access: "public" },
      },
      null,
      2,
    )}\n`,
  )
  writeFileSync(
    join(directory, "README.md"),
    `# ${name}\n\nThis version is a placeholder with no code. Install a real release:\n\n\`\`\`bash\nnpm install ${name}@latest\n\`\`\`\n`,
  )

  console.log(`Publishing ${name}@${PLACEHOLDER_VERSION} (no code).`)
  console.log("npm will ask you to log in and for your 2FA code if needed.\n")

  const published = npm(
    [
      "publish",
      "--access",
      "public",
      "--tag",
      PLACEHOLDER_TAG,
      "--provenance=false",
    ],
    { cwd: directory },
  )

  if (published.status !== 0) process.exit(published.status ?? 1)
} finally {
  rmSync(directory, { recursive: true, force: true })
}

console.log(`
Done. Next, on npmjs.com open ${name} → Settings:
  1. Trusted publishing → GitHub Actions: organization gydr-ai, the
     repository from package.json, workflow release.yml, environment npm,
     allow "npm publish".
  2. Publishing access → "Require two-factor authentication and disallow tokens".
After the first real release, deprecate the placeholder:
  npm deprecate ${name}@${PLACEHOLDER_VERSION} "Placeholder with no code; use ${name}@latest"
`)
