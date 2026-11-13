# Contributing

Thanks for helping. This is a small, security-focused package, so changes
are reviewed carefully and the bar for new options is high.

## Before you start

- **Security issues**: follow [SECURITY.md](SECURITY.md), never a public issue.
- **Bugs**: open an issue with a minimal reproduction.
- **Features**: open an issue first to agree the design before writing code.

## Development

Requirements: Node.js 22.23.5+, 24.22.3+ or 26.13.1+ and pnpm 11
(`corepack enable`).

```bash
pnpm install
pnpm check   # lint, type-check, tests with coverage, build
```

Useful scripts:

| Script               | What it does                                   |
| -------------------- | ---------------------------------------------- |
| `pnpm test`          | Run the test suite                             |
| `pnpm test:coverage` | Tests with coverage thresholds                 |
| `pnpm lint`          | ESLint (strict, type-aware) and Prettier check |
| `pnpm format`        | Apply Prettier and ESLint fixes                |
| `pnpm typecheck`     | TypeScript, including the tests                |
| `pnpm build`         | Emit `dist/`                                   |

## Pull requests

- Keep each pull request to one change, with tests that fail without it.
- The pull request **title** must be a
  [Conventional Commit](https://www.conventionalcommits.org/): it becomes the
  squash commit, and the release tooling reads it to choose the next version.
  - `fix: ...` → patch release
  - `feat: ...` → minor release
  - `feat!: ...` or a `BREAKING CHANGE:` footer → major release
  - `docs:`, `test:`, `ci:`, `chore:`, `refactor:` → no release
- Do not edit `CHANGELOG.md` or the version: they are generated.
- New runtime dependencies need a strong reason. Every dependency is
  attack surface for everyone who installs this package.

## Licence

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
