package calibrate

import "math/big"

// Tier is how much creep trusts a model, from the calibration result. The
// planner bounds its strategy by it (#12).
type Tier string

const (
	TierS Tier = "S" // small: bounded steps; the default when anything is unmeasured
	TierM Tier = "M"
	TierL Tier = "L"
)

// maxInvalidPercent is the share of task replies that may fail to decode
// before the structured-output check fails. Exactly this share passes.
const maxInvalidPercent = 5

// tierRule is what a model needs for one tier. Every bound is inclusive,
// and score bounds apply to the Wilson lower bound, not the point score,
// so a class with few tasks cannot earn a tier by luck.
type tierRule struct {
	tier         Tier
	tools        bool     // the tool-calling check must pass
	contextBytes int      // minimum effective context
	overallLower *big.Rat // minimum lower bound over all tasks
	classLower   *big.Rat // minimum lower bound of every class
}

// tierRules go from the highest tier down; the first one met wins.
//
// With 14 tasks a class needs 11 right for L (lower 0.524) and 7 for M
// (0.268); with 8 tasks, 7 (0.529) and 5 (0.306). Over 100 tasks L needs
// 84 right and M 65. A model that answers "safe" to everything gets 50
// (and 4 of 8 in the smaller classes, lower 0.215), so it stays S.
func tierRules() []tierRule {
	return []tierRule{
		{tier: TierL, tools: true, contextBytes: 128 << 10, overallLower: big.NewRat(3, 4), classLower: big.NewRat(1, 2)},
		{tier: TierM, tools: false, contextBytes: 32 << 10, overallLower: big.NewRat(11, 20), classLower: big.NewRat(1, 4)},
	}
}

// StructuredCheck counts task replies that never decoded into a valid
// answer, retries included.
type StructuredCheck struct {
	Total   int  `json:"total"`
	Invalid int  `json:"invalid"`
	Passed  bool `json:"passed"`
}

func newStructuredCheck(total, invalid int) StructuredCheck {
	passed := total > 0 && invalid*100 <= total*maxInvalidPercent
	return StructuredCheck{Total: total, Invalid: invalid, Passed: passed}
}

// ToolCheck counts tool-calling probes answered with the right tool and
// the exact argument. It passes only when every probe does.
type ToolCheck struct {
	Probes  int  `json:"probes"`
	Correct int  `json:"correct"`
	Passed  bool `json:"passed"`
}

func newToolCheck(probes, correct int) ToolCheck {
	return ToolCheck{Probes: probes, Correct: correct, Passed: probes > 0 && correct == probes}
}

// ContextCheck is the largest probe size, in bytes, the model answered,
// with every smaller size answered too; 0 when it failed the first.
type ContextCheck struct {
	EffectiveBytes int `json:"effective_bytes"`
}

// assignTier returns the highest tier whose rule r meets, or TierS. It
// reads only counts and integers, so a recorded run always gets the same
// tier on every platform.
func assignTier(r Result) Tier {
	for _, rule := range tierRules() {
		if meets(r, rule) {
			return rule.tier
		}
	}
	return TierS
}

func meets(r Result, rule tierRule) bool {
	if !r.Structured.Passed || (rule.tools && !r.Tools.Passed) {
		return false
	}
	if r.Context.EffectiveBytes < rule.contextBytes {
		return false
	}
	if !lowerAtLeast(r.Overall.Correct, r.Overall.Total, rule.overallLower) {
		return false
	}
	for _, c := range r.Classes {
		if !lowerAtLeast(c.Correct, c.Total, rule.classLower) {
			return false
		}
	}
	return len(r.Classes) == len(Classes())
}
