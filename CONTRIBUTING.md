# Contributing to creep

Thanks for helping. The most valuable contributions are often not code:

- **False negative**: a vulnerability `creep` missed. Use the *False negative* issue form with a minimal vulnerable example. It becomes a test case.
- **False positive**: a finding that is wrong. Use the *False positive* issue form.
- **Model results**: calibration or benchmark results with your model. Post them in [Discussions → Show and tell](https://github.com/Ludocius/creep/discussions/categories/show-and-tell).
- **Recipes and model presets**: data, not code. See the issue forms.

## Before you start

1. Look for an existing issue. If none exists, open one before writing code that is larger than a typo fix.
2. Changes that add a dependency, change a public contract (CLI flags, exit codes, JSON/SARIF output, config keys) or touch security-sensitive areas need an [ADR](docs/adr/0000-template.md) first.
3. Security-sensitive areas: `internal/gateway`, `internal/redact`, `internal/egress`, `internal/sandbox`, `internal/planner`. PRs touching them get the `security-sensitive` label and require the threat-model checklist.

## Development setup

You need Go, make and git. Nothing else: dev tools are pinned in `go.mod` and run with `go tool`.

```sh
make check                          # fmt, vet, budget and tests (CI also runs golangci-lint, govulncheck, gitleaks)
make budget                         # dependency allowlist, module/binary caps, file length, workflow pinning
make test PKG=./internal/redact     # one package
make map                            # regenerate docs/map.md
```

Tests never call a real model. They replay recorded responses from `testdata/replay`:

```sh
creep scan testdata/apps/flask-sqli --record   # record with a local model (Ollama)
go test ./...                                   # replays deterministically, no keys needed
```

## Pull requests

- One logical change per PR. Small PRs get reviewed faster.
- Branch from `main`. PRs are squash-merged; `main` has linear history.
- Title in [Conventional Commits](https://www.conventionalcommits.org/) format: `feat(redact): detect JWTs`.
- **Signed commits** (SSH or GPG) are required. See [GitHub docs](https://docs.github.com/authentication/managing-commit-signature-verification).
- **DCO**: every commit needs `Signed-off-by` (`git commit -s`). By signing off you certify the [Developer Certificate of Origin](https://developercertificate.org/). We do not use a CLA.
- Add a release-note label (see below).

### Release-note labels

| Label | Section in release notes |
|---|---|
| `breaking` | ⚠️ Breaking changes |
| `security` | 🔒 Security |
| `affects-results` | 🎯 Changes that affect results (prompts, rules, calibration) |
| `type/feature` | ✨ New |
| `type/bug`, `type/false-positive`, `type/false-negative` | 🐛 Fixes |
| `type/docs` | 📚 Documentation |
| `type/chore`, `skip-changelog` | hidden |

`affects-results` matters: when prompts, rules or calibration change, users' results and CI baselines can shift.

## AI-assisted contributions

Welcome. Declare it in the PR template. You are responsible for every line you sign off. Agents should read [AGENTS.md](AGENTS.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
