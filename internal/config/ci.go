package config

import "strings"

// ciVars are environment variables that mark a CI run. Most providers
// (GitHub Actions, GitLab, CircleCI, Travis, Buildkite, Bitbucket) set CI;
// Azure Pipelines sets TF_BUILD and Jenkins sets JENKINS_URL.
var ciVars = []string{"CI", "TF_BUILD", "JENKINS_URL"}

// InCI reports whether getenv describes a CI run: any of ciVars is set to a
// value other than "", "0" or "false". This is the one definition creep uses;
// in CI nothing may prompt and endpoint consent must come from the policy.
// A CI run this misses is still safe: with no stored consent and no
// terminal, the consent prompt declines and nothing is sent.
func InCI(getenv func(string) string) bool {
	for _, name := range ciVars {
		v := strings.ToLower(strings.TrimSpace(getenv(name)))
		if v != "" && v != "0" && v != "false" {
			return true
		}
	}
	return false
}
