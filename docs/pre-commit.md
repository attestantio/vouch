# Pre-commit pilot

These hooks are a proof of concept for team discussion. Installing them is optional.
They do not replace CI.

## Setup

Install [pre-commit](https://pre-commit.com/#install) 4.6.2 and put your Go bin
directory on PATH. From the repository root, prepare the custom linter and tools:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
golangci-lint custom
go install golang.org/x/tools/cmd/goimports@v0.38.0
go install github.com/AntiD2ta/gosilent/cmd/gosilent@0ce62be09464
pre-commit install
```

The custom build reads the existing `.custom-gcl.yml` and `.golangci.yml`.
A stock golangci-lint binary cannot provide the configured attgo plugin.
The generated `custom-gcl` binary is ignored by Git.

Use a Go toolchain compatible with the `go 1.25.5` directive in `go.mod`.
The pilot's commit checks and full suite pass locally.

## Commit checks

Goimports formats selected Go files using gofmt rules and organizes imports.
There is no separate gofmt pass. SSZ files ending in `_ssz.go` are excluded from this formatter pass.
These are filename exclusions, not general detection of generated-file headers.

Lint analyzes packages but reports diagnostics only on staged changed lines.
The staged patch uses explicit path prefixes regardless of your Git configuration.
The repository's existing lint settings, including test-file exclusions, remain
unchanged. Lint runs when Go files are added or modified; deletion-only, module-only,
and lint-config-only commits do not trigger it. Compilation and lint-configuration
errors block commits when that hook runs. The tidy check still runs on every commit.

`go mod tidy -diff` checks dependency drift without modifying `go.mod` or `go.sum`.
Whitespace checks operate on whole selected files, not only edited lines. They can
add unrelated whitespace changes to a commit, including whitespace inside raw
strings. Inspect formatter and whitespace edits, restage intended changes, and
rerun the checks.

Files added over 500 KB are rejected. Gitleaks scans staged content with redacted
output. The upstream hook revisions are pinned in the config.

## Push checks

`gosilent test ./...` runs the full Go suite and shortens its output.
It tests the current working tree, not the exact refs being pushed. Push from a
clean checkout of the branch you intend to publish; pushing another branch or
keeping staged or untracked Go edits can test different code. CI remains the
independent test of the pushed commits.

To run checks manually:

```sh
pre-commit run
pre-commit run --hook-stage pre-push
```

Avoid `pre-commit run --all-files` for this pilot unless you intend to review and
restage repository-wide formatting and whitespace changes. Manual file selection
does not replace a staged-patch lint check.
