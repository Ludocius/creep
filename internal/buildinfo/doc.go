// Package buildinfo reports which build of creep is running.
//
// Release builds inject version and commit with -ldflags -X; plain
// `go build` and `go install` builds fall back to the metadata the Go
// toolchain embeds, so bug reports always carry a usable identifier.
package buildinfo
