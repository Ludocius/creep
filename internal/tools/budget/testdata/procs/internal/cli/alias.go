// Fixture: parsed by the budget tests, never built.
package cli

import o "os"

func start() { o.StartProcess("/bin/sh", nil, nil) }
