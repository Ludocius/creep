package config

// Config is the effective configuration. Every leaf field is a key, named by
// the dotted path of its yaml tags (model.endpoint). The desc tags feed
// schema/config.schema.json, which a test keeps in sync with these structs.
type Config struct {
	Model       Model       `yaml:"model"`
	Egress      Egress      `yaml:"egress"`
	Gates       Gates       `yaml:"gates"`
	Budget      Budget      `yaml:"budget"`
	Report      Report      `yaml:"report"`
	Scanners    Scanners    `yaml:"scanners"`
	Sandbox     Sandbox     `yaml:"sandbox"`
	Calibration Calibration `yaml:"calibration"`
	Output      Output      `yaml:"output"`
	Log         Log         `yaml:"log"`
}

type Model struct {
	Contract string `yaml:"contract" desc:"How creep talks to the model: an HTTP API (openai, anthropic) or a local command."`
	Endpoint string `yaml:"endpoint" desc:"Base URL of the model API (http:// or https://). Cannot be set in the project file."`
	Name     string `yaml:"name" desc:"Model name sent to the endpoint."`
	Tier     string `yaml:"tier" desc:"Model tier; selects the prompt variant."`
}

type Egress struct {
	Allow []string `yaml:"allow" desc:"Hosts (host or host:port) the gateway may contact. Cannot be set in the project file."`
}

type Gates struct {
	PR      string `yaml:"pr" desc:"Pull request gate: <status>:<severity> or none. Exit 1 when a finding reaches it."`
	Nightly string `yaml:"nightly" desc:"Nightly gate: <status>:<severity> or none."`
}

type Budget struct {
	MaxTokens int `yaml:"max_tokens" desc:"Maximum model tokens per scan."`
	MaxCalls  int `yaml:"max_calls" desc:"Maximum model calls per scan."`
}

type Report struct {
	Formats []string `yaml:"formats" desc:"Report files written after a scan."`
}

type Scanners struct {
	Enabled []string `yaml:"enabled" desc:"Optional external scanners to run when installed."`
}

type Sandbox struct {
	Enabled bool   `yaml:"enabled" desc:"Run proofs of concept in a container (v0.2). The sandbox never has internet access."`
	Runtime string `yaml:"runtime" desc:"Container runtime for the sandbox."`
}

type Calibration struct {
	CacheDays int `yaml:"cache_days" desc:"Days a model calibration stays valid."`
}

type Output struct {
	Format string `yaml:"format" desc:"Terminal output format (flag --format)."`
}

type Log struct {
	Level string `yaml:"level" desc:"Log level (flag --log-level)."`
}

// Value ranges for integer keys.
const (
	minCacheDays = 1
	maxCacheDays = 365
)

// enums lists the allowed values of each enumerated key; for list keys it
// constrains every element. Validation and the schema both read it.
var enums = map[string][]string{
	"model.contract":   {"openai", "anthropic", "command"},
	"model.tier":       {"small", "medium", "large"},
	"report.formats":   {"json", "markdown", "sarif"},
	"scanners.enabled": {"gitleaks", "osv-scanner", "semgrep"},
	"sandbox.runtime":  {"docker", "podman"},
	"output.format":    {"text", "json", "sarif", "markdown"},
	"log.level":        {"debug", "info", "warn", "error"},
}

// projectForbidden keys decide where scanned code is sent; a hostile repo
// could otherwise point them at itself through its creep.yaml.
var projectForbidden = map[string]bool{
	"model.endpoint": true,
	"egress.allow":   true,
}

// Enum returns the allowed values of key, or nil when it is not enumerated.
func Enum(key string) []string {
	return append([]string(nil), enums[key]...)
}

// Defaults returns the built-in safe defaults (design.md: CI gates, 30-day
// calibration cache, sandbox off until v0.2).
func Defaults() Config {
	return Config{
		Model:       Model{Contract: "openai", Tier: "medium"},
		Gates:       Gates{PR: "probable:critical", Nightly: "verified:high"},
		Budget:      Budget{MaxTokens: 2_000_000, MaxCalls: 500},
		Report:      Report{Formats: []string{"json", "markdown", "sarif"}},
		Scanners:    Scanners{Enabled: []string{}},
		Sandbox:     Sandbox{Runtime: "docker"},
		Egress:      Egress{Allow: []string{}},
		Calibration: Calibration{CacheDays: 30},
		Output:      Output{Format: "text"},
		Log:         Log{Level: "info"},
	}
}
