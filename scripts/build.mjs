// Builds the package: one minified ESM bundle with esbuild, plus type
// declarations from tsc. Dependencies stay external.
import { spawnSync } from "node:child_process"
import { rmSync } from "node:fs"
import { build } from "esbuild"

rmSync("dist", { recursive: true, force: true })

const result = await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  minify: true,
  keepNames: true,
  sourcemap: true,
  sourcesContent: true,
  legalComments: "none",
  packages: "external",
  outfile: "dist/index.js",
  metafile: true,
  logLevel: "warning",
})

if (result.warnings.length > 0) {
  console.error(`esbuild reported ${result.warnings.length} warning(s)`)
  process.exit(1)
}

const tsc = spawnSync(
  process.execPath,
  [
    "node_modules/typescript/bin/tsc",
    "-p",
    "tsconfig.build.json",
    "--emitDeclarationOnly",
    "--declaration",
    "--declarationMap",
    "false",
    "--stripInternal",
    "--outDir",
    "dist/types",
  ],
  { stdio: "inherit" },
)

if (tsc.status !== 0) process.exit(tsc.status ?? 1)
