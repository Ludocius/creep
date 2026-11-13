# Governance

## Roles

- **Maintainers** review and merge PRs, triage issues, cut releases and handle security reports.
- **Contributors** are everyone who opens issues, discussions or PRs.

Current maintainers:

| GitHub | Areas |
|---|---|
| @Ludocius | All (founder) |

## Decisions

- Day-to-day decisions happen in issues and PRs.
- Decisions that change architecture, public contracts or dependencies are recorded as [ADRs](docs/adr/).
- While there is a single maintainer, the founder decides. With three or more maintainers, decisions that cannot reach consensus go to a simple majority of maintainers.

## Becoming a maintainer

Sustained, high-quality contributions over at least three months, including reviews. Any maintainer can nominate; the existing maintainers decide.

## Review rules

- Single-maintainer phase: PR + required checks; review requires 0 approvals and code-owner review is off. Nobody bypasses the checks.
- With two or more maintainers: two approvals for security-sensitive paths (see `.github/CODEOWNERS`).

## Code of Conduct

Maintainers enforce the [Code of Conduct](CODE_OF_CONDUCT.md).
