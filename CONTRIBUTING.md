# Contributing to creep

Thanks for helping. The most valuable contributions are often not code:

- **False negative**: a vulnerability `creep` missed. Use the *False negative* issue form with a minimal vulnerable example. It becomes a test case.
- **False positive**: a finding that is wrong. Use the *False positive* issue form.
- **Model results**: calibration or benchmark results with your model. Post them in [Discussions → Show and tell](https://github.com/sneakercreepers/creep/discussions/categories/show-and-tell).
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
- **Signed commits** (SSH or GPG) are recommended and will become required on `main` once the maintainer has signing set up ([#49](https://github.com/sneakercreepers/creep/issues/49)). See [GitHub docs](https://docs.github.com/authentication/managing-commit-signature-verification).
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

## Repository rules

Rulesets live in [`.github/rulesets/`](.github/rulesets/) and are applied with `make rulesets` (creates or updates by name), which also applies [`.github/settings/`](.github/settings/): Actions permissions (full-SHA pinning required) and the `release` environment. Change them by PR, never only in the UI.

- `main`: PR required, squash only, linear history, no force push or deletion, and all CI jobs green. No bypass actors, not even admins.
- `release-tags`: `v*` tags can never be moved or deleted. `release-tag-creation`: only repository admins can create `v*` tags.
- Single-maintainer phase: PRs need 0 approvals and code-owner review is off. With two or more maintainers, raise approvals and turn on `require_code_owner_review` (see [GOVERNANCE.md](GOVERNANCE.md)).

## Releasing

Maintainers only. Versions follow [SemVer](https://semver.org/); pre-releases are `vX.Y.Z-rc.N`. Before 1.0 a minor release may break things and says so under ⚠️ Breaking changes.

1. Close the milestone: every issue done or moved. Run the release pentest ([ADR 0004](docs/adr/0004-pentester-per-release.md)) and the architecture review with its wiki diagram update ([ADR 0005](docs/adr/0005-auditor-architecture-review.md)); a confirmed Critical or High blocks the release.
2. Tag a release candidate on `main` and push it: `git tag -a v0.1.0-rc.1 -m v0.1.0-rc.1 && git push origin v0.1.0-rc.1`.
3. Verify the artifacts, checksums, provenance and draft notes. Notes come from [`.github/release.yml`](.github/release.yml); anything labelled `affects-results` must be called out, because users' results and baselines will shift.
4. Tag the final version on the same commit: `v0.1.0`.
5. Approve the `release` environment deployment. The environment only accepts `v*` tags, needs the maintainer's approval (admins cannot bypass it) and is the only place release credentials (OIDC) are available.

Tags are immutable (ruleset) and so are published releases (immutable releases are enabled). A mistake means a new version, never a moved tag.

Rulesets cannot enforce "a `v*` tag points to a commit on `main`". The release workflow ([#19](https://github.com/sneakercreepers/creep/issues/19)) checks ancestry before building and refuses a tag whose commit is on neither `main` nor a `release/*` branch.

**Hotfix** (patch without shipping unreleased work from `main`):

1. Fix on `main` first, through a normal PR.
2. Branch from the release tag: `git switch -c release/v0.1 v0.1.0` (reuse the branch if it exists) and push it.
3. Cherry-pick the squash commit: `git cherry-pick -x -s <sha>`, then push.
4. Tag the patch from that branch: `git tag -a v0.1.1 -m v0.1.1 && git push origin v0.1.1`, then follow Releasing steps 3 to 5.

## AI-assisted contributions

Welcome. Declare it in the PR template. You are responsible for every line you sign off. Agents should read [AGENTS.md](AGENTS.md).

Model-assisted changes go through the agent loop **developer → tester → pentester → auditor** (details in [AGENTS.md](AGENTS.md#workflow-spec-driven), rationale in [ADR 0002](docs/adr/0002-agent-loop-scope.md)). Developer, tester and auditor share context. The pentester gets no shared context. The pentester runs once per version, over the whole version diff before the release is tagged, and on every pull request from an external contributor ([ADR 0004](docs/adr/0004-pentester-per-release.md)). A confirmed Critical or High from the release pentest blocks the release. The `security-sensitive` label, which only maintainers apply, marks what the release pentest must cover first. If the auditor sees security impact in an unlabeled change, it asks a maintainer to add the label so the release pentest covers it. Link the tester verdict, the security review (when the pentester ran) and the auditor decision in the PR. A confirmed Critical or High finding blocks the merge. Documentation-only changes run only the auditor (only `*.md` or `docs/`; not code, workflows, settings or the policy files). The auditor triages every open finding and adds the follow-up issues to the project board. Changing or removing this loop needs an ADR and maintainer approval.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
