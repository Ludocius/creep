// Package calibrate measures the user's model per vulnerability class.
//
// It exists because public benchmarks are in every model's training data, so
// a score on them says little about the model in front of us. Calibration
// tasks are generated instead: Generate turns a seed into TaskCount tasks by
// mutating vulnerability templates.
//
//   - Templates are data, not code (docs/architecture.md §5, §8): each one is
//     a directory under templates/ holding template.json (class, language,
//     identifier pools, sink lines and markers) and a vulnerable.tmpl and
//     safe.tmpl twin. Adding a template adds a directory, not Go code.
//   - A mutation only renames identifiers, drawn from the template's own
//     pools, and inserts neutral constant lines before the sink. Loading
//     refuses a pool value that is not a plain identifier, is a keyword,
//     repeats in another pool or already appears in the template, so a
//     rename can never alias a name the code uses. The ground truth (class,
//     vulnerable or safe, sink line) is therefore fixed by the template, and
//     the twin markers in template.json let tests check every task for it.
//   - The generator is pure: seed in, tasks out, no I/O beyond the embedded
//     files. It reads randomness only from a PCG source seeded with the seed
//     and draws through intN, so the tasks depend on the PCG algorithm and
//     this package alone, not on math/rand helpers that may change between
//     Go releases. Golden hashes in the tests pin the output; changing a
//     template changes them, which is intended: it changes calibration
//     results, and the PR needs the affects-results label.
//   - Half the tasks are vulnerable and half are their safe twins, spread
//     round-robin over every template, then shuffled so position says
//     nothing about the label.
//
// Templates hold no real secret or hostname; hosts use the reserved
// .invalid top-level domain.
//
// Run scores a model on those tasks (run.go, score.go, tier.go):
//   - Every call is a models.Complete through the caller's *models.HTTP, so
//     consent, budget and egress.log apply; every prompt is first passed
//     whole through the run's redact.File, like a repository file, and its
//     marker counts go to egress.log. Only the numbered code reaches the
//     model, never a task's template, ID, class or label.
//   - Calls are made one at a time in a fixed order (tasks, then tool
//     probes, then context probes), so a recorded run replays exactly.
//   - Scoring: a safe twin is right only when called safe; a vulnerable
//     task needs its class and a line within 2 of the sink (the source line
//     may sit just above it). A reply that stays invalid after retries is
//     wrong and counts against the structured-output check. Any other
//     failure ends the run with no Result.
//   - Each class gets a 95% Wilson interval. Tiers use the interval's lower
//     bound, never the point score, because classes have as few as 8 tasks;
//     the comparison is exact rational arithmetic, so the tier of a recorded
//     run is the same on every platform. A class with no tasks is
//     unmeasured and keeps the model at tier S.
//   - Probes, seeded on their own PCG stream: tool calling (pick the right
//     tool, copy the argument exactly) and effective context (find one
//     assignment in 8, 32, then 128 KiB of similar ones, stopping at the
//     first miss). A probe refused for its size (HTTP 400 or 413, or the
//     token budget) is a miss, not a failed run.
//   - The Result records the seed, a hash of the task set and
//     PromptVersion, so a cached result (#91) is tied to what it measured.
package calibrate
