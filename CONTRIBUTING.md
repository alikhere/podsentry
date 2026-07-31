# Contributing to podsentry

## Prerequisites

- Go 1.22 or later
- `golangci-lint` (optional, for linting)
- `make`

## Development Setup

```bash
git clone git@github.com:alikhere/podsentry.git
cd podsentry
go mod tidy
make build
make test
```

## Adding a New PSS Rule

1. Create or open the appropriate file in `internal/pss/` (`baseline.go` or `restricted.go`).
2. Define a struct implementing the `Rule` interface:
   - `ID() string` — unique identifier, e.g. `PSS-BL-008`
   - `Name() string` — human-readable name
   - `Level() Level` — `LevelBaseline` or `LevelRestricted`
   - `Check(spec *corev1.PodSpec) []Violation`
3. Register the rule in `baselineRules()` or `restrictedRules()`.
4. Add tests in the corresponding `_test.go` file covering pass and fail scenarios.

## Adding a New Report Formatter

1. Add a new file in `internal/report/`, e.g. `markdown.go`.
2. Implement a `WriteXMarkdown(w io.Writer, ...)` function.
3. Wire it into the relevant command in `cmd/` by extending the format switch statement.
4. Update the `--output` flag description in `cmd/root.go`.

## Branch Naming

- `feat/<short-description>` — new feature
- `fix/<short-description>` — bug fix
- `chore/<short-description>` — maintenance, dependency updates
- `test/<short-description>` — test additions or fixes

## Commit Message Format

```
<type>(<scope>): <short description>
```

Types: `feat`, `fix`, `test`, `chore`, `docs`, `refactor`

Examples:
```
feat(pss): add AppArmor baseline rule
fix(loader): handle missing kind field gracefully
test(userns): add inspector edge case tests
```

## Pull Request Guidelines

- Keep PRs focused on a single concern.
- All new code must have tests.
- Run `make test` and confirm all tests pass before opening a PR.
- Run `make lint` if `golangci-lint` is installed.
- PR description should explain what changed and why.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Exported functions must have a godoc comment.
- No comments explaining what the code does — only why when it is non-obvious.
- Errors must be wrapped with context: `fmt.Errorf("doing X: %w", err)`.
- No `panic` in library code.
- Use strong types; avoid `interface{}` except at JSON boundaries.
