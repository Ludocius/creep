# ADR 0002: Shared context in the agent loop, pentester only on security-sensitive issues

- **Status:** Accepted
- **Date:** 2026-11-13
- **Deciders:** @Ludocius

## Context

Since #55 every model-assisted change runs four independent agents with no shared context: developer → tester → pentester → auditor. Two costs showed up in #4/#68:

- Each agent re-reads the issue, the diff and the code from scratch, so a cycle spends most of its tokens rebuilding context the previous agent already had.
- The pentester runs on every change. On #68 it produced the findings behind eight follow-up issues (#69–#76); useful on redaction, but the same depth on a non-security change mostly adds iterations.

The pentester is the only agent whose value comes from independence: a reviewer that sees the developer's reasoning tends to accept it.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Keep the loop as is | Strongest independence everywhere | Highest token cost; long iterations on every change |
| B. Shared context for all four agents | Cheapest | The security review anchors on the developer's reasoning |
| C. Shared context except the pentester; pentester only on `security-sensitive` issues, label set by maintainers | Cheap on routine changes; security review stays independent where it matters | Relies on the label being right |

## Decision

Option C. Independence matters for the security review, not for implementing and checking acceptance criteria, so it is kept only there. Restricting the label to maintainers stops a contributor from skipping the pentester by leaving the label off a risky change. Requiring the auditor to escalate unlabeled changes with security impact covers labels that are missing by mistake.

## Consequences

- Developer, tester and auditor share context (issue, diff, test output, earlier verdicts). On a blocking finding the developer continues with the findings instead of a fresh agent starting over.
- The pentester gets only the issue, the diff and the repository.
- `make budget` requires the new rules in AGENTS.md and CONTRIBUTING.md, and the PR template checkbox (`internal/tools/budget/policy.go`).
- Only maintainers may apply `security-sensitive`. This is policy only for now; a workflow that removes the label when someone else applies it is a follow-up.
- Changes already labeled `security-sensitive` (#3 sub-issues, redaction fixes, sandbox, config hardening) keep the full loop.
