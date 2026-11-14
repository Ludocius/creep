package report

import (
	"fmt"
	"io"
	"sort"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	toolURI      = "https://github.com/sneakercreepers/creep"
	srcRoot      = "%SRCROOT%"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
	Properties  sarifRunProps     `json:"properties"`
}

type sarifRunProps struct {
	SchemaVersion int          `json:"creep_schema_version"`
	Incomplete    bool         `json:"incomplete"`
	Coverage      Coverage     `json:"coverage"`
	DataHandling  DataHandling `json:"data_handling"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifNotification struct {
	Descriptor sarifDescriptor `json:"descriptor"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
}

type sarifDescriptor struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Kind       string          `json:"kind"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties sarifResultProp `json:"properties"`
}

type sarifResultProp struct {
	ID     string `json:"creep_id"`
	Status Status `json:"status"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
	Region   *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIF writes r as a SARIF 2.1.0 log for GitHub code scanning. Only
// verified and probable findings become results; an incomplete run has
// executionSuccessful false and an error notification, and every
// not-evaluated file is a warning notification with its reason.
func WriteSARIF(w io.Writer, r *Report) error {
	rules, index := sarifRules(r.Findings)
	run := sarifRun{
		Tool:        sarifTool{Driver: sarifDriver{Name: r.Tool.Name, Version: r.Tool.Version, InformationURI: toolURI, Rules: rules}},
		Invocations: []sarifInvocation{sarifInvocationOf(r)},
		Results:     sarifResults(r.Findings, index),
		Properties:  sarifRunProps{SchemaVersion: r.SchemaVersion, Incomplete: r.Run.Incomplete, Coverage: r.Coverage, DataHandling: r.DataHandling},
	}
	if err := writeInertJSON(w, sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}); err != nil {
		return fmt.Errorf("write SARIF report: %w", err)
	}
	return nil
}

// sarifRules lists one rule per class that has a result, sorted, and maps
// each class to its index.
func sarifRules(findings []Finding) ([]sarifRule, map[string]int) {
	var classes []string
	seen := map[string]bool{}
	for _, f := range findings {
		if sarifLevel(f.Status) != "" && !seen[f.Class] {
			seen[f.Class] = true
			classes = append(classes, f.Class)
		}
	}
	sort.Strings(classes)
	rules := make([]sarifRule, len(classes))
	index := make(map[string]int, len(classes))
	for i, c := range classes {
		rules[i] = sarifRule{ID: c, ShortDescription: sarifMessage{Text: "creep vulnerability class " + c}}
		index[c] = i
	}
	return rules, index
}

func sarifResults(findings []Finding, index map[string]int) []sarifResult {
	results := []sarifResult{}
	for _, f := range findings {
		level := sarifLevel(f.Status)
		if level == "" {
			continue
		}
		results = append(results, sarifResult{
			RuleID: f.Class, RuleIndex: index[f.Class], Kind: "fail", Level: level,
			Message:    sarifMessage{Text: fmt.Sprintf("%s finding %s (%s)", f.Class, f.ID, f.Status)},
			Locations:  []sarifLocation{fileLocation(f.Path, f.Line)},
			Properties: sarifResultProp{ID: f.ID, Status: f.Status},
		})
	}
	return results
}

// sarifLevel is "" for statuses that are not code-scanning alerts.
func sarifLevel(s Status) string {
	switch s {
	case StatusVerified:
		return "error"
	case StatusProbable:
		return "warning"
	}
	return ""
}

func sarifInvocationOf(r *Report) sarifInvocation {
	inv := sarifInvocation{ExecutionSuccessful: !r.Run.Incomplete, Notifications: []sarifNotification{}}
	if r.Run.Incomplete {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "creep/incomplete"},
			Level:      "error",
			Message:    sarifMessage{Text: "incomplete run (" + r.Run.Reason + "): not everything was evaluated; this is not a clean result"},
		})
	}
	for _, n := range r.Coverage.NotEvaluated {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "creep/not-evaluated/" + string(n.Reason)},
			Level:      "warning",
			Message:    sarifMessage{Text: "file not evaluated: " + string(n.Reason)},
			Locations:  []sarifLocation{fileLocation(n.Path, 0)},
		})
	}
	return inv
}

func fileLocation(path string, line int) sarifLocation {
	loc := sarifLocation{Physical: sarifPhysical{Artifact: sarifArtifact{URI: uriPath(path), URIBaseID: srcRoot}}}
	if line > 0 {
		loc.Physical.Region = &sarifRegion{StartLine: line}
	}
	return loc
}
