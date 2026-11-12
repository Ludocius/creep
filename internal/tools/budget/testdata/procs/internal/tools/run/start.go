// Fixture: parsed by the budget tests, never built.
package run

import "os"

func start() { os.StartProcess("go", nil, nil) }
