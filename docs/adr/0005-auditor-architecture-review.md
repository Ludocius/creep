# ADR 0005: Auditor reviews architecture; per-version architecture review

- **Status:** Accepted
- **Date:** 2026-11-13
- **Deciders:** @Ludocius
- **Amends:** [ADR 0002](0002-agent-loop-scope.md) (auditor duties only)

## Context

No agent in the loop checks a change against [`docs/architecture.md`](../architecture.md). The layer table will be enforced by `make budget` (#119), but contracts, module depth, test focus and bounded work are not mechanical. The document also had no engineering principles for the developer to follow and a reviewer to cite, and nothing kept the GitHub wiki diagrams in step with the code.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. New architect agent in the loop | Dedicated reviewer | One more agent per PR; more tokens and cycles; changes the loop |
| B. Auditor checks each PR against `architecture.md`, plus a per-version holistic review | No new role; the auditor already sees the shared context | The auditor's prompt grows |
| C. Rely on `make budget` only | Cheapest | Misses everything that is not mechanical |

## Decision

Option B. The auditor checks every PR against `docs/architecture.md`: layers, stable contracts, engineering principles (§8) and fitness functions (§9). It reports each deviation as a finding rated by real impact, like any other finding. Before each version is tagged, alongside the release pentest of ADR 0004, the auditor runs a **per-version architecture review**: it reviews the whole version diff against the principles and fitness functions, runs the benchmarks, opens an issue for each maintainability or scalability finding, and updates the Mermaid diagrams (context, pipeline, components and layers) on the GitHub wiki Architecture page. The wiki links back to `docs/architecture.md`, which stays the source of truth.

What decided it: the auditor already holds the issue, diff and verdicts, so the check costs one more lens, not one more agent.

## Consequences

- Roles, order, context rules and blocking rules of the loop are unchanged. Architecture findings use the same severity scale; Medium and below become follow-up issues.
- A new architectural property needs a fitness function in §9, not only prose.
- The testing convention in AGENTS.md now asks for edge cases, failure paths and security protections, not trivial happy paths.
- The release process (#19) gains the architecture review and the wiki update as a step next to the release pentest.
