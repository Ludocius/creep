## What and why

<!-- One logical change. Link the issue: "Closes #123". -->

Closes #

## Type

- [ ] Feature
- [ ] Fix (bug, false positive or false negative)
- [ ] Docs
- [ ] Chore / CI / refactor

## Checklist

- [ ] `make check` passes locally
- [ ] Tests added or updated (new model behavior has a replay fixture)
- [ ] Commits are signed and have `Signed-off-by` (DCO)
- [ ] Release-note label added (`breaking`, `security`, `affects-results`, `type/*` or `skip-changelog`)
- [ ] New direct dependency or public-contract change → ADR linked: <!-- docs/adr/NNNN-... -->

## Security-sensitive changes

<!-- Required if this PR touches internal/gateway, redact, egress, sandbox, planner, prompts/ or .github/workflows. Delete otherwise. -->

- [ ] Secrets and PII still never reach the gateway unredacted
- [ ] The planner still receives only IDs, enums and booleans
- [ ] No new network path outside `internal/gateway`
- [ ] Model output is still never executed on the host
- [ ] `docs/threat-model.md` reviewed (updated if needed)

## Results impact

- [ ] This changes prompts, rules or calibration (`affects-results`). Bench before/after: <!-- link or table -->

## AI assistance

- [ ] No AI assistance
- [ ] AI-assisted (tool/model: ______ ). I reviewed and understand every line I'm signing off.
- [ ] AI-assisted: ran the agent loop developer → tester → pentester → auditor. Tester verdict, security review and auditor decision: <!-- links -->
- [ ] The pentester ran with no shared context, or was skipped because the issue is not labeled `security-sensitive`.
- [ ] Documentation-only (`*.md` or `docs/`): ran only the auditor. Auditor decision: <!-- link -->
