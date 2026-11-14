// Package testapps guards the deliberately vulnerable apps in testdata/apps.
//
// creep needs, for every vulnerability class it claims, a small vulnerable
// app and a safe twin, to measure both detection and false positives. Those
// apps are only data: the go command never builds testdata, and the tests in
// this package keep them that way and keep their expected findings honest.
// The package has no product code and the layers table (internal/tools/*)
// keeps it out of the binary.
//
// Layout, one directory per app:
//
//	testdata/apps/<app>/expected.json
//	testdata/apps/<app>/vulnerable/<source files>
//	testdata/apps/<app>/safe/<source files, same names>
//
// The expected findings live beside the two variants, not inside them, so a
// scan of either variant never sees them. The source files carry the same
// neutral header in both variants, so nothing in the scanned text says which
// one is vulnerable.
//
// expected.json, schema_version 1 (decoded strictly, unknown fields fail):
//
//	{
//	  "schema_version": 1,
//	  "app": "<directory name>",
//	  "language": "python" | "javascript",
//	  "framework": "<free text>",
//	  "vulnerable": [{"class", "file", "line", "route", "sink"}, ...],
//	  "safe": []
//	}
//
// class is one of a closed set (see classes in the tests); file is relative to
// the variant directory; line is 1-based and must contain sink verbatim, so a
// stale line number fails; route must appear verbatim in the file. A finding
// list for safe must be present and empty. Adding a field or a class is a
// schema change: bump schema_version.
//
// The apps never run outside the sandbox. TestAppsMatchExpected rejects
// anything but source files of the app's language and expected.json: no
// package manifests, lockfiles, install hooks, build or run scripts, test files
// a Python or JS runner would collect, Go files or symlinks.
// TestNothingExecutesApps fails when a Makefile, workflow, composite action,
// Dockerfile, compose file, package.json (its scripts run under npm) or shell
// script mentions testdata/apps, or when Go code that can start programs (os/exec, syscall,
// os.StartProcess) names it. Like make budget, it is a static backstop that
// reads text; review stays required.
package testapps
