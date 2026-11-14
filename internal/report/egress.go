package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Bounds on egress.log reading. A log over them is an error, not a partial
// summary. Lines are far smaller in practice (one request's metadata).
const (
	maxEgressLine      = 64 << 10
	maxEgressEndpoints = 256
	maxEndpointModels  = 64
	maxRedactionLabels = 256
	maxOutcomes        = 64
)

// OutcomeNoResult counts requests whose result line is missing: the request
// was sent (the request line is write-ahead) but its outcome is unknown.
const OutcomeNoResult = "no_result"

// ErrEgressLog is wrapped by every egress.log summary error.
var ErrEgressLog = errors.New("egress.log cannot be summarized")

// DataHandling is what left the machine, summarized from egress.log.
type DataHandling struct {
	Requests   int              `json:"requests"`
	Bytes      int64            `json:"bytes"`
	Endpoints  []EndpointUsage  `json:"endpoints"`
	Redactions map[string]int64 `json:"redactions"` // markers by label
}

// EndpointUsage is one endpoint's share. Endpoint and Models come from the
// log, which records the configured endpoint (scheme, host, path).
type EndpointUsage struct {
	Endpoint     string           `json:"endpoint"`
	Models       []string         `json:"models"`
	Requests     int              `json:"requests"`
	Bytes        int64            `json:"bytes"`
	InputTokens  int64            `json:"input_tokens"`
	OutputTokens int64            `json:"output_tokens"`
	Outcomes     map[string]int64 `json:"outcomes"`
}

// egressLine is the subset of the gateway's request and result lines the
// summary reads. The line contract is additive, so unknown fields are fine.
type egressLine struct {
	V          int              `json:"v"`
	Type       string           `json:"type"`
	ID         string           `json:"id"`
	Endpoint   string           `json:"endpoint"`
	Model      string           `json:"model"`
	Bytes      int64            `json:"bytes"`
	Redactions map[string]int64 `json:"redactions"`
	Outcome    string           `json:"outcome"`
	Tokens     *struct {
		Input  int64 `json:"input"`
		Output int64 `json:"output"`
	} `json:"tokens"`
}

type egressSummary struct {
	dh      DataHandling
	byName  map[string]int // endpoint -> index in dh.Endpoints
	pending map[string]int // request ID -> endpoint index, until its result
}

// SummarizeEgress reads an egress.log stream. An empty log means no data
// left the machine. Any line it cannot account for (bad JSON, newer v,
// unknown type, result without request, negative counts) fails closed.
func SummarizeEgress(r io.Reader) (DataHandling, error) {
	s := egressSummary{byName: map[string]int{}, pending: map[string]int{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxEgressLine)
	for n := 1; sc.Scan(); n++ {
		if err := s.add(sc.Bytes()); err != nil {
			return DataHandling{}, fmt.Errorf("%w: line %d: %w", ErrEgressLog, n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return DataHandling{}, fmt.Errorf("%w: %w", ErrEgressLog, err)
	}
	for _, i := range s.pending {
		s.dh.Endpoints[i].Outcomes[OutcomeNoResult]++
	}
	return s.dh.normalized(), nil
}

func (s *egressSummary) add(raw []byte) error {
	var l egressLine
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&l); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if l.V != 1 {
		return fmt.Errorf("unsupported v %d", l.V)
	}
	switch l.Type {
	case "request":
		return s.addRequest(l)
	case "result":
		return s.addResult(l)
	}
	return fmt.Errorf("unknown type %q", l.Type)
}

func (s *egressSummary) addRequest(l egressLine) error {
	if _, dup := s.pending[l.ID]; dup || l.ID == "" || l.Bytes < 0 {
		return errors.New("request without a unique ID or with negative bytes")
	}
	i, err := s.endpoint(l.Endpoint)
	if err != nil {
		return err
	}
	ep := &s.dh.Endpoints[i]
	ep.Requests++
	ep.Bytes += l.Bytes
	s.dh.Requests++
	s.dh.Bytes += l.Bytes
	if err := addModel(ep, l.Model); err != nil {
		return err
	}
	if err := s.addRedactions(l.Redactions); err != nil {
		return err
	}
	s.pending[l.ID] = i
	return nil
}

func (s *egressSummary) addResult(l egressLine) error {
	i, ok := s.pending[l.ID]
	if !ok || l.Outcome == "" {
		return errors.New("result without a pending request or outcome")
	}
	delete(s.pending, l.ID)
	ep := &s.dh.Endpoints[i]
	if _, ok := ep.Outcomes[l.Outcome]; !ok && len(ep.Outcomes) >= maxOutcomes {
		return errors.New("too many distinct outcomes")
	}
	ep.Outcomes[l.Outcome]++
	if l.Tokens == nil {
		return nil
	}
	if l.Tokens.Input < 0 || l.Tokens.Output < 0 {
		return errors.New("negative token count")
	}
	ep.InputTokens += l.Tokens.Input
	ep.OutputTokens += l.Tokens.Output
	return nil
}

func (s *egressSummary) endpoint(name string) (int, error) {
	if i, ok := s.byName[name]; ok {
		return i, nil
	}
	if len(s.dh.Endpoints) >= maxEgressEndpoints {
		return 0, errors.New("too many endpoints")
	}
	s.dh.Endpoints = append(s.dh.Endpoints, EndpointUsage{Endpoint: name, Outcomes: map[string]int64{}})
	s.byName[name] = len(s.dh.Endpoints) - 1
	return len(s.dh.Endpoints) - 1, nil
}

func addModel(ep *EndpointUsage, model string) error {
	for _, m := range ep.Models {
		if m == model {
			return nil
		}
	}
	if len(ep.Models) >= maxEndpointModels {
		return errors.New("too many models for one endpoint")
	}
	ep.Models = append(ep.Models, model)
	return nil
}

func (s *egressSummary) addRedactions(counts map[string]int64) error {
	if s.dh.Redactions == nil {
		s.dh.Redactions = map[string]int64{}
	}
	for label, n := range counts {
		if n < 0 {
			return errors.New("negative redaction count")
		}
		if _, ok := s.dh.Redactions[label]; !ok && len(s.dh.Redactions) >= maxRedactionLabels {
			return errors.New("too many redaction labels")
		}
		s.dh.Redactions[label] += n
	}
	return nil
}

// normalized sorts endpoints and models and replaces nil collections with
// empty ones, so JSON prints [] and {} and every format is deterministic.
func (d DataHandling) normalized() DataHandling {
	out := d
	out.Endpoints = make([]EndpointUsage, len(d.Endpoints))
	for i, ep := range d.Endpoints {
		ep.Models = append([]string{}, ep.Models...)
		sort.Strings(ep.Models)
		ep.Outcomes = copyCounts(ep.Outcomes)
		out.Endpoints[i] = ep
	}
	sort.Slice(out.Endpoints, func(i, j int) bool { return out.Endpoints[i].Endpoint < out.Endpoints[j].Endpoint })
	out.Redactions = copyCounts(d.Redactions)
	return out
}

func copyCounts(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
