package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// logVersion is the egress.log line format version.
const logVersion = 1

// maxResponseBytes bounds a model reply read into memory.
const maxResponseBytes = 8 << 20

// maxLabelBytes bounds Model and Purpose so one call cannot bloat the log.
const maxLabelBytes = 256

// Outcomes recorded on result lines. They are a closed set: no error text
// reaches egress.log, because transport errors quote the full URL.
const (
	OutcomeResponse  = "response"
	OutcomeTransport = "transport_error"
	OutcomeTooLarge  = "response_too_large"
	OutcomeRedirect  = "redirect_refused"
)

// ErrRedirectNotFollowed means a model endpoint answered with a redirect.
// Send does not follow it, because following would re-send the body.
var ErrRedirectNotFollowed = errors.New("model endpoint redirected; redirects are not followed")

// ErrLabel means Model or Purpose is empty or longer than maxLabelBytes.
var ErrLabel = errors.New("model and purpose must be 1-256 bytes")

// ErrResponseTooLarge means a reply exceeded maxResponseBytes.
var ErrResponseTooLarge = errors.New("model response too large")

// Call is one model request. Payload must already be redacted: repository
// text comes from a FileScan Fragment, with its Redactions. It is sent and
// stored byte for byte.
type Call struct {
	Endpoint   string         // absolute http(s) URL; the client enforces egress.allow
	Model      string         // logged
	Purpose    string         // logged, e.g. "reader" or "calibration"
	Payload    []byte         // exact request body; logged only as sha256 and file
	Redactions map[string]int // marker label -> count in Payload; logged
	Header     http.Header    // request headers (credentials); never logged
	// Usage extracts token counts from the reply body for the result line.
	// Provider adapters supply it; nil records no tokens.
	Usage func(body []byte) (Usage, bool)
}

// Usage is the token count a provider reports for one call.
type Usage struct {
	InputTokens  int `json:"input"`
	OutputTokens int `json:"output"`
}

// Reply is the answer to one Send.
type Reply struct {
	ID     string
	Status int
	Body   []byte
}

// requestLine is written and synced before any byte is sent.
type requestLine struct {
	V           int            `json:"v"`
	Type        string         `json:"type"`
	ID          string         `json:"id"`
	Time        string         `json:"time"`
	Endpoint    string         `json:"endpoint"`
	Model       string         `json:"model"`
	Purpose     string         `json:"purpose"`
	Bytes       int            `json:"bytes"`
	SHA256      string         `json:"sha256"`
	Redactions  map[string]int `json:"redactions"`
	PayloadFile string         `json:"payload_file"`
}

// resultLine follows the request line with the same ID once the call ends.
// A request line with no result line means creep stopped mid-call.
type resultLine struct {
	V       int    `json:"v"`
	Type    string `json:"type"`
	ID      string `json:"id"`
	Time    string `json:"time"`
	Outcome string `json:"outcome"`
	Status  int    `json:"status,omitempty"`
	Tokens  *Usage `json:"tokens,omitempty"`
}

// Send checks consent for the endpoint's origin, records call in the log,
// then POSTs it with client and records the result. Write-ahead: the
// payload file and the request line are written and synced first, and any
// failure there returns before the request is built,
// so nothing is sent that egress.log does not show. A failure to write the
// result line returns an error and no reply, so an unlogged answer is never
// used.
//
// The payload is copied first, so a caller changing its slice mid-call
// cannot make the bytes sent differ from the bytes hashed and stored.
// Redirects are not followed: a 307 or 308 would send the body again to a
// path the log does not show. Returned errors never quote the endpoint's
// userinfo or query string.
func (l *EgressLog) Send(ctx context.Context, client *Client, call Call) (*Reply, error) {
	if client == nil {
		return nil, errors.New("gateway call: nil client")
	}
	call.Payload = bytes.Clone(call.Payload)
	endpoint, err := checkCall(call)
	if err != nil {
		return nil, err
	}
	if err := l.checkConsent(call.Endpoint, endpoint); err != nil {
		return nil, err
	}
	id, err := l.logRequest(call, endpoint)
	if err != nil {
		return nil, err
	}
	status, body, sendErr := post(ctx, withoutRedirects(client.hc), call)
	if err := l.logResult(id, call, status, body, sendErr); err != nil {
		return nil, errors.Join(sendErr, err)
	}
	if sendErr != nil {
		return nil, fmt.Errorf("gateway call %s: %w", id, sendErr)
	}
	return &Reply{ID: id, Status: status, Body: body}, nil
}

// checkConsent runs before the payload file, the request line or any
// connection, so a refused call leaves no trace in the run directory:
// egress.log records only what was attempted, and a refusal is reported to
// the caller as a *ConsentError instead. logged is the endpoint without
// credentials, the only form an error may quote.
func (l *EgressLog) checkConsent(raw, logged string) error {
	if l.consent == nil {
		return fmt.Errorf("gateway call: %w", &ConsentError{Endpoint: logged, Err: errors.New("no consent configured")})
	}
	u, _ := url.Parse(raw) // checkCall parsed it already
	if err := l.consent.check(u); err != nil {
		return fmt.Errorf("gateway call: %w", err)
	}
	return nil
}

// checkCall validates the logged labels and returns the endpoint as logged:
// scheme, host and path only, so credentials in userinfo or the query string
// never reach egress.log.
func checkCall(call Call) (string, error) {
	if !validLogField(call.Model) || !validLogField(call.Purpose) {
		return "", fmt.Errorf("gateway call: %w", ErrLabel)
	}
	u, err := url.Parse(call.Endpoint)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", errors.New("gateway call: endpoint must be an absolute URL")
	}
	return withoutCredentials(u), nil
}

// withoutCredentials keeps scheme, host and path, dropping userinfo, query
// and fragment, where API keys travel.
func withoutCredentials(u *url.URL) string {
	clean := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}
	return clean.String()
}

// scrubURLError rebuilds the *url.Error that http.Client returns, which
// quotes the full request URL, with that URL stripped of credentials.
func scrubURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	clean := "(unparseable URL)"
	if u, perr := url.Parse(ue.URL); perr == nil {
		clean = withoutCredentials(u)
	}
	return &url.Error{Op: ue.Op, URL: clean, Err: ue.Err}
}

// withoutRedirects returns a copy of client that hands back any redirect
// response instead of following it.
func withoutRedirects(client *http.Client) *http.Client {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func validLogField(s string) bool {
	return s != "" && len(s) <= maxLabelBytes
}

func (l *EgressLog) logRequest(call Call, endpoint string) (string, error) {
	id := rand.Text()
	file, err := l.writePayload(id, call.Payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(call.Payload)
	redactions := call.Redactions
	if redactions == nil {
		redactions = map[string]int{}
	}
	return id, l.writeLine(requestLine{
		V: logVersion, Type: "request", ID: id, Time: now(),
		Endpoint: endpoint, Model: call.Model, Purpose: call.Purpose,
		Bytes: len(call.Payload), SHA256: hex.EncodeToString(sum[:]),
		Redactions: redactions, PayloadFile: file,
	})
}

func (l *EgressLog) logResult(id string, call Call, status int, body []byte, sendErr error) error {
	line := resultLine{V: logVersion, Type: "result", ID: id, Time: now(), Outcome: OutcomeResponse, Status: status}
	switch {
	case errors.Is(sendErr, ErrResponseTooLarge):
		line.Outcome = OutcomeTooLarge
	case errors.Is(sendErr, ErrRedirectNotFollowed):
		line.Outcome = OutcomeRedirect
	case sendErr != nil:
		line.Outcome = OutcomeTransport
	case call.Usage != nil:
		if u, ok := call.Usage(body); ok {
			line.Tokens = &u
		}
	}
	return l.writeLine(line)
}

// post sends the payload and reads at most maxResponseBytes of the reply.
func post(ctx context.Context, client *http.Client, call Call) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, call.Endpoint, bytes.NewReader(call.Payload))
	if err != nil {
		return 0, nil, errors.New("build request: invalid endpoint") // the parse error quotes the URL
	}
	// Without GetBody the transport cannot replay the body (HTTP/1 retry on
	// a dropped reused connection, HTTP/2 retry, redirects), so each logged
	// request line is sent at most once.
	req.GetBody = nil
	for k, v := range call.Header {
		req.Header[k] = v
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, scrubURLError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, nil, fmt.Errorf("status %d: %w", resp.StatusCode, ErrRedirectNotFollowed)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(body) > maxResponseBytes {
		return resp.StatusCode, nil, ErrResponseTooLarge
	}
	return resp.StatusCode, body, nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
