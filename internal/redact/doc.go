// Package redact replaces secrets and personal data with stable markers before
// any text leaves the machine.
//
// It exists because creep sends fragments of the scanned repository to a
// model, and the repository can hold credentials and personal data. The
// gateway runs every payload through a Redactor first (AGENTS.md invariant 2).
//
// Detection:
//   - Secrets: the gitleaks default rules (rules/gitleaks.toml), vendored byte
//     for byte from a pinned release and evaluated with the standard regexp
//     package, so gitleaks is data, not a dependency. Version, URL and MIT
//     license are in NOTICE; a test pins the file's SHA-256 and rule count.
//   - Secrets the vendored rules miss: local rules in the same format
//     (rules/local.toml), so gitleaks.toml stays upstream. They cover Docker
//     access tokens (dckr_pat_, dckr_oat_), Discord webhook ids and tokens,
//     and OpenAI scoped keys (sk-proj-, sk-svcacct-, sk-admin-). The vendored
//     openai-api-key rule ends in \b, which fails after a key whose last
//     character is "-"; it is the only vendored rule with a \b right after a
//     possible "-" (TestTrailingBoundaryAfterDash fails if a re-vendor adds
//     one). A local id may not repeat a vendored one.
//   - PII: email addresses, card numbers (Luhn), US SSNs (dashed, SSA-valid
//     ranges), Spanish DNI and NIE (control letter) and Brazilian CPF (two
//     check digits, dotted or not). Checksums keep ordinary numbers in code
//     unmasked.
//   - Credentials with no fixed format, which gitleaks misses: the password
//     in scheme://user:password@host, the value of password, passwd, pwd,
//     passphrase and secret keys (quoted or bare, references such as ${VAR}
//     left alone), and a bare 40-character AWS secret key when an AWS access
//     key id is in the same input (credentials.go).
//   - Private keys cut by a fragment boundary, which the gitleaks rule misses
//     because it needs BEGIN and END in the same text (pem.go). After a BEGIN
//     ... PRIVATE KEY line (any variant, PGP BLOCK included) everything is
//     masked through the matching END line or the end of the fragment; before
//     an END line, back to its BEGIN line or the start of the fragment. A key
//     body with neither (a middle fragment) is masked as a run of two or more
//     lines ending in a base64 token of 40 to 76 characters (lengths may
//     differ, since a boundary leaves partial lines), or one such line that
//     reaches the start or end of the fragment, directly or through one short
//     partial line; the run takes in a short line on either side. Prefixed digests
//     (go.sum "h1:", "sha256:") and lowercase hex do not count. This can mask
//     ordinary data, which is the safe side.
//
// When matches overlap they are merged and the most specific label names the
// marker; each part is also remembered, so it is masked when it shows up
// alone in a later fragment.
//
// The rules file is read by a tiny reader for the TOML subset it uses
// (toml.go) instead of a generator that converts it to JSON. Both need the same
// parsing, but this way the embedded file stays identical to upstream and can
// be verified by hash, there is no second artifact to keep in sync, and any
// syntax outside the subset is an error caught by the tests. Only id, regex,
// secretGroup and keywords are used. Keywords gate rules exactly as in
// gitleaks (a rule runs only if one of its keywords occurs, case-insensitive);
// without that, running every regex on every fragment is far too slow.
// Entropy thresholds and allowlists are ignored on purpose: they exist to cut
// false positives in reports, while a redactor should rather mask too much
// than leak. Matches may overlap, so a lazy match opened by earlier text cannot
// end inside a real secret and hide the rest of it. Like gitleaks, the masked
// value is the secret group (or the first non-empty group), so variable names
// and quotes around it stay readable for the model.
//
// Markers: each distinct value gets <SECRET_<RULE>_<N>> or <PII_<KIND>_<N>>,
// numbered per kind, and keeps it for the life of the Redactor (one per run),
// so the same secret has the same marker in every fragment. Values seen before
// are also masked where no rule matches them any more. The reverse map lives
// only in memory: it has no exported field, no encoding method, prints as a
// fixed string, and the package imports nothing that writes files (enforced by
// a test). Unredact is for local display only.
//
// Marker-like text already present in the input ("<SECRET_", "<PII_",
// "<ESC_") is escaped by inserting ESC_, so repository text can neither forge a
// marker that un-redacts to a real secret nor collide with one.
//
// Whole files: File redacts a file before anything cuts it, so a secret is
// never seen split across fragments. Callers that fragment repository text
// (the gateway, #3, and the reader, #13) must fragment only text returned by
// File, never raw file content: the per-fragment detectors in Redact can only
// guess at a key or token a boundary cut, and a guess can miss (a partial
// line of a key body, a token's tail with no prefix). File finds private keys
// over the whole file (from BEGIN to END, BEGIN to the end of the file, the
// start of the file to END, and bare key bodies), then runs the other
// detectors on chunks of at most MaxInputBytes cut at line ends, each
// reaching chunkOverlap (4 KiB) back into the previous one. Every line lies in
// one chunk with the 4 KiB before it, and no non-exempt rule reaches more than
// a few hundred bytes back from its last line (derived per regex by
// TestChunkOverlapBound), so every match is seen whole by some chunk. Spans
// from all chunks are merged before markers are written, so a value found
// twice in an overlap is masked once and keeps one marker for the run.
// Redact still applies every detector to each fragment, as defense in depth.
//
// Performance: Go's regexp is linear-time (RE2), so no input can trigger
// catastrophic backtracking. Each Redact call is still bounded to
// MaxInputBytes, each File call to MaxFileBytes (1 MiB) with lines of at most
// MaxLineBytes, and both fail closed above their caps. The constants document
// the measured worst case. Values from earlier fragments are re-masked through
// an index of 8-byte windows, linear in the input however many values the run
// knows. A rule whose matches overlap densely stops searching again after a
// fixed multiple of the input and masks the rest of it instead.
//
// Run limits: one run remembers at most about 128k values or 32 MiB of them
// (a private key without an END line is one value up to the end of its file),
// and at most 256 values whose every 8-byte window already indexes 16 others
// (runs of one byte or short pattern, such as "xxxxxxxx" placeholders).
// When a new value does not fit, that call and every later call on the
// Redactor return ErrRunFull and no output, because a value the run cannot
// remember would not be re-masked in later fragments. Callers must stop
// sending that run's fragments and report the scan as incomplete.
package redact
