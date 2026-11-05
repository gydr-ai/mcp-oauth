// Smoke-tests the built package: every public export is present with the
// expected type, declarations exist, and no declaration leaks an internal
// symbol.
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"

const expected = {
  createMcpAuth: "function",
  createAesGcmSealer: "function",
  createOidcProvider: "function",
  createMemoryStore: "function",
  escapeHtml: "function",
  GrantInactiveError: "function",
  IdentityProviderError: "function",
  McpAuthConfigError: "function",
  SealerError: "function",
  UpstreamTokenError: "function",
}

const mod = await import(new URL("../dist/index.js", import.meta.url).href)
const failures = []

for (const [name, type] of Object.entries(expected)) {
  if (typeof mod[name] !== type) {
    failures.push(`export ${name} is ${typeof mod[name]}, expected ${type}`)
  }
}

for (const name of Object.keys(mod)) {
  if (!(name in expected)) failures.push(`unexpected export ${name}`)
}

if (!existsSync("dist/types/index.d.ts")) {
  failures.push("dist/types/index.d.ts is missing")
}

const internal = new Set()

/** Collect names declared with an `@internal` tag in the sources. */
function collectInternal(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)

    if (entry.isDirectory()) {
      collectInternal(path)
      continue
    }

    const text = readFileSync(path, "utf8")
    const pattern =
      /@internal[\s\S]*?\*\/\s*export\s+(?:async\s+)?(?:function|class|const|interface|type)\s+(\w+)/g

    for (const match of text.matchAll(pattern)) internal.add(match[1])
  }
}

/** Check one declaration directory for leaked internal names. */
function scanDeclarations(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)

    if (entry.isDirectory()) {
      scanDeclarations(path)
      continue
    }

    if (!path.endsWith(".d.ts")) continue

    const text = readFileSync(path, "utf8")

    for (const name of internal) {
      if (
        new RegExp(
          `\\bexport\\s+(?:declare\\s+)?(?:function|class|const|interface|type)\\s+${name}\\b`,
        ).test(text)
      ) {
        failures.push(`${path} declares internal symbol ${name}`)
      }
    }
  }
}

collectInternal("src")

if (existsSync("dist/types")) scanDeclarations("dist/types")

if (failures.length > 0) {
  console.error(failures.join("\n"))
  process.exit(1)
}

console.log(
  `dist OK: ${Object.keys(expected).length} exports, ${internal.size} internal symbols kept out of declarations`,
)
