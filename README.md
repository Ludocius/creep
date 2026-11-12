<div align="center">

# SneakerCreepers · `creep`

**Find vulnerabilities in your own code with whatever model you have — small or large, local or cloud.**
`creep` measures what your model can actually do, adapts its strategy, verifies findings by running them, and tells you plainly what it did *not* check.

[![v0.1 progress](https://img.shields.io/github/milestones/progress-percent/Ludocius/creep/1?label=v0.1)](https://github.com/Ludocius/creep/milestone/1)
[![Open issues](https://img.shields.io/github/issues/Ludocius/creep)](https://github.com/Ludocius/creep/issues)
[![Go Reference](https://pkg.go.dev/badge/github.com/Ludocius/creep.svg)](https://pkg.go.dev/github.com/Ludocius/creep)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Status](https://img.shields.io/badge/status-pre--alpha-orange)

</div>

> [!WARNING]
> **Pre-alpha.** Nothing is released yet. This README describes the v0.1 target; follow progress on the [Roadmap project](https://github.com/users/Ludocius/projects/4) and the [v0.1 milestone](https://github.com/Ludocius/creep/milestones).

---

## Why

| Problem with current tools | What `creep` does |
|---|---|
| A clean scan with an 8B model is not worth the same as one with a frontier model, but reports don't say so | Calibrates **your** model per vulnerability class and reports what was covered, partial, or **not evaluated** |
| Tied to one vendor or model | Model-agnostic: any OpenAI-compatible or Anthropic API, or **any CLI** (`claude -p`, Gemini CLI, `codex exec`, `ollama run`…) |
| Reports whatever the model says | A finding is **verified** only when a proof of concept runs in an isolated sandbox (v0.2) |
| You can't see what leaves your machine | Secrets are always redacted and every model call is logged in `egress.log` |

## Install

> Available from **v0.1**.

**Prebuilt binary** (Windows, macOS, Linux · amd64/arm64) from [Releases](https://github.com/Ludocius/creep/releases), then verify it:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/Ludocius/creep/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

**With Go** (1.24+):

```sh
go install github.com/Ludocius/creep/cmd/creep@latest
```

**From source:**

```sh
git clone https://github.com/Ludocius/creep && cd creep
make build   # binary in ./bin/creep
```

## Quickstart

```sh
creep init     # detects your stack and an available model, writes creep.yaml
creep doctor   # checks model, config and (optional) Docker before anything fails
creep scan .   # static analysis + model triage + coverage report
```

Only what changed, for pre-commit or PRs:

```sh
creep scan --diff origin/main --sarif out.sarif
```

## Bring your own model

`creep` never ships, hosts or bills a model. You bring one; you pay for your own usage.

**HTTP contract** — any OpenAI-compatible endpoint or Anthropic:

```yaml
# creep.yaml
model: ollama/qwen3:8b
```

**Command contract** — any CLI that reads a prompt on stdin and prints JSON. Uses your own subscription quota:

```yaml
# creep.yaml
model:
  type: command
  run: claude -p --tools "" --strict-mcp-config --output-format json
```

> [!IMPORTANT]
> The model reads untrusted code, so it must not have tools. `creep` sends a **tool canary** (a trap prompt) before every scan and refuses to run if the CLI can execute commands or write files.

## Privacy

| Mode | What leaves your machine |
|---|---|
| `local-only` | Nothing. Local models only. |
| `redacted` *(default)* | Minimal code fragments, with secrets and PII replaced by stable placeholders |
| `full` | Whole files, still redacted |

Always on, not configurable: secret redaction, `egress.log`, no telemetry. An organization policy can lock these settings for every repo.

## Output

- **SARIF** for GitHub code scanning, GitLab, DefectDojo, SonarQube
- **JSON** with a stable `schema_version`
- **Markdown** report with a coverage section and a data-handling section
- Exit codes: `0` nothing blocking · `1` gate exceeded · `2` config error · `3` model or sandbox error

## Roadmap

| Version | Scope |
|---|---|
| **v0.1** | CLI, static analysis, model calibration, planner/reader triage, coverage report, privacy gateway |
| v0.2 | Optional sandbox (Docker/Podman) with PoC against HEAD, GitHub Action, baseline |
| v0.3 | Read-only MCP mode, YAML recipes, public `creep-bench` |
| v1.0 | Organization policy, signed releases with provenance, HTML report |
| v2 · v3 | Differential verification · fix with oracle |

v0.1 scans **Python** (Flask, FastAPI) and **JavaScript/TypeScript** (Express).

## Scope and responsible use

`creep` only attacks targets it builds itself from local source code, inside a sandbox with no internet access. There is no `--url` option, and there will never be evasion, persistence, lateral movement or mass scanning. If you find a vulnerability in someone else's project, follow their disclosure policy.

## Contributing

Contributions are welcome — especially **false positive** and **false negative** reports, which become test cases. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). AI-assisted contributions are fine: see [AGENTS.md](AGENTS.md).

## Security

Do not open public issues for vulnerabilities in `creep`. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
