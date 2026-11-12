package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/Ludocius/creep/internal/exitcode"
)

func printUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString("creep finds vulnerabilities in local source code.\n\n")
	b.WriteString("Usage:\n  creep [global flags] <command> [flags] [args]\n\n")
	b.WriteString("Commands:\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "  %-8s %s\n", c.name, c.summary)
	}
	fmt.Fprintf(&b, "  %-8s %s\n\n", "help", "show this help")
	b.WriteString(globalFlagsHelp())
	b.WriteString("\n")
	b.WriteString(exitcode.Help())
	fmt.Fprint(w, b.String())
}

func printCommandUsage(w io.Writer, c command) {
	fmt.Fprintf(w, "Usage:\n  creep %s [flags]\n\n%s.\n\n%s\n%s", c.name, c.summary, globalFlagsHelp(), exitcode.Help())
}

func globalFlagsHelp() string {
	d := defaultOptions()
	return fmt.Sprintf("Global flags (before or after the command):\n"+
		"  --config <path>     config file to use instead of the default layers\n"+
		"  --format <format>   output format: %s (default %q)\n"+
		"  --log-level <level> log level: %s (default %q)\n",
		strings.Join(formats, ", "), d.format, strings.Join(logLevels, ", "), d.logLevel)
}
