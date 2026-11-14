package calibrate

import _ "embed" // the system prompts are versioned data in prompts/

// The system prompts, one per call kind. Calibration runs before a tier is
// known, so each has a single variant; PromptVersion names them.
var (
	//go:embed prompts/task.txt
	taskSystem string
	//go:embed prompts/tools.txt
	toolsSystem string
	//go:embed prompts/context.txt
	contextSystem string
)
