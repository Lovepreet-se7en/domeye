# DOMEye — agent guide

## Quick start

```powershell
go build -o domeye .          # or: make build
domeye scan <url>             # single target
domeye scan --file urls.txt   # batch
```

## Key commands

| Command | Meaning |
|---------|---------|
| `go build -o domeye .` | Build binary (Makefile: `make build`) |
| `go test ./...` | Run all tests (`make test`) |
| `make clean` | Remove built binary |

## Repo map

- `main.go` → `cmd/` (Cobra CLI, 3 subcommands: `scan`, `version`, `root`)
- `internal/scanner/` — HTTP fetch + HTML parse (goquery). Auto-prepends `https://` to URLs lacking a scheme.
- `internal/analyzer/` — 7 check types: XSS, CSP, DOM, SourceSink, AdvancedDOM, PrototypePollution, DOMClobbering. `--all` is default.
- `internal/output/` — text (stdout), JSON (`--output json`), HTML (`scan_report.html`).
- `test_vulnerable.html` — manual test page with intentional vulns (for `domeye scan` against local file or `file://`).

## Quirks & conventions

- **No test files exist** — `go test ./...` passes trivially. Tests are manual via `test_vulnerable.html`.
- **Binary `domeye` is committed** — no `.gitignore`. The binary is tracked; build overwrites it in-place.
- **`--all` is implicit** — running without `--xss`, `--csp`, `--dom`, `--sourcesink` runs every check.
- `--concurrency` defaults to 5; `--timeout` defaults to 30s.
- Version declared in `cmd/version.go:9` (currently `2.2.1`).
- Go 1.21, module `github.com/Lovepreet-se7en/domeye`.
