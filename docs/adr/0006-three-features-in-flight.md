# ADR 0006: Up to three features in flight

- **Status:** Accepted
- **Date:** 2026-11-13
- **Deciders:** @Ludocius
- **Amends:** [ADR 0002](0002-agent-loop-scope.md) (merge concurrency only)

## Context

AGENTS.md allowed one feature at a time. With the loop running per feature, the maintainer found this too slow on 2026-11-13: v0.1 still has many open issues, and most of them touch separate packages.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Keep one feature at a time | No merge conflicts; simplest | Too slow; reviews wait on each other |
| B. Up to three in flight, in different packages or layers, rebased before merge | About three times the throughput; conflicts stay rare | Rebases and re-runs of CI before each merge |
| C. No limit | Fastest on paper | Overlapping edits, stale branches, review load the maintainer cannot follow |

## Decision

Option B. Up to three features may be in flight at once. They are chosen from different packages or layers so they do not edit the same files. Each runs the full loop on its own, and each branch is rebased on `main` and re-checked (CI green) before its squash merge.

What decided it: the maintainer asked for the throughput, and picking features that do not share files keeps the main cost of parallel work, conflicting edits, small.

## Consequences

- The loop itself is unchanged: roles, order (developer → tester → auditor; pentester per version and on external PRs, ADR 0004), context rules and blocking rules stay as they are.
- Shared documents such as AGENTS.md **Current state** may still conflict; the later branch resolves them during its rebase.
- A branch that is green but behind `main` must be rebased and pass CI again before merge.
