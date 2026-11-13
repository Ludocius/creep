# Security Policy

`creep` reads untrusted code and talks to language models, so we expect it to be a target. Thank you for helping keep it safe.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting:
[Report a vulnerability](https://github.com/sneakercreepers/creep/security/advisories/new)

Please include the version, the configuration (`creep config explain`, with secrets removed), steps to reproduce and the impact you expect.

## What we commit to

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Initial assessment | 7 days |
| Fix released — critical | ≤ 7 days |
| Fix released — high | ≤ 30 days |
| Fix released — medium/low | Next minor release |

We publish a GitHub Security Advisory and request a CVE for confirmed vulnerabilities, and credit reporters who want it.

## Supported versions

| Version | Supported |
|---|---|
| Latest minor | ✅ |
| Previous minor | ✅ security fixes only |
| Older | ❌ |

Before v1.0, only the latest minor release is supported.

## In scope

- Secrets or code leaving the machine despite redaction or `local-only` mode
- Prompt injection that changes the planner's decisions or causes command execution
- Sandbox escape or network egress from the sandbox
- Tool canary bypass in the command contract
- Supply-chain issues in our releases (signatures, provenance, SBOM)

## Out of scope

- Vulnerabilities `creep` fails to detect in *your* code — open a *False negative* issue instead
- Findings in third-party scanners (semgrep, osv-scanner, gitleaks) — report them upstream
