// Package gateway is the only code in creep that may touch the network.
//
// It exists so that every byte leaving the machine passes one reviewable
// choke point (AGENTS.md invariants 1, 2 and 5):
//   - It is the only package allowed to import net, net/http, crypto/tls and
//     the other networking packages. `make budget` fails the build when any
//     other package, test files and dev tooling included, imports them or
//     reaches them through a dependency; golangci-lint's depguard rule gives
//     the same feedback in editors.
//   - Every model call is redacted first: repository text is passed through
//     redact.File before it is fragmented, every fragment through the run's
//     Redactor before it is sent, and a run that returns redact.ErrRunFull
//     stops sending and is reported as incomplete.
//   - Every request is recorded in egress.log, so a user can audit exactly
//     what was sent and where.
//   - It connects only to configured model endpoints; creep has no telemetry.
//
// NewClient enforces where requests may go, in this order and before any
// DNS lookup or dial:
//   - Allowlist: the URL host and effective port must match an egress.allow
//     entry. "host" covers only the scheme's default port (443 or 80);
//     "host:port" covers only that port. Hosts must be LDH DNS names whose
//     last label starts with a letter, or canonical IP literals without a
//     zone, so numeric tricks (2130706433, 0x7f.1, 0177.0.0.1, 127.1) never
//     reach a resolver. IPv4-mapped IPv6 is compared as IPv4.
//   - TLS: http:// is allowed only to loopback hosts, meaning exactly the
//     name "localhost", 127.0.0.0/8 and ::1. Names that resolve to loopback
//     (localhost.attacker.com, 127.0.0.1.nip.io) are not loopback hosts.
//   - Redirects: only to the same scheme, host and port as the first
//     request, at most 10. https→http and port changes are refused.
//
// The dialer then pins addresses: each allowlisted host is resolved once per
// client and later dials use only the pinned IPs, while TLS still verifies
// the certificate and sends SNI and Host for the hostname. A slow lookup
// holds only its own host. "localhost" is never resolved; it means
// 127.0.0.1, then ::1. A DNS answer containing any non-public address
// (loopback, private, CGNAT, link-local and cloud metadata, multicast, or
// NAT64, SIIT and 6to4 forms of those) is refused whole, always. A model on a
// private network is reached by allowlisting and requesting its IP literal
// ("10.0.0.5:8443"); that entry never vouches for a name resolving to it.
//
// Dial, TLS handshake and response-header waits have fixed default timeouts
// (client.go) until they get config keys.
//
// Proxy environment variables are ignored: a proxy resolves names itself,
// which would bypass the address checks and pinning above.
//
// Every model call goes through EgressLog.Send, which writes
// <run>/egress.log, one JSON object per line, mode 0600, opened with
// O_APPEND and never through a link or onto a file others can read, own or
// reach through a second hard link. Send copies the payload before hashing
// it, follows no redirects (that would re-send the body unlogged), and
// strips userinfo and query from every error it returns.
// Each call gets a random ID and two lines:
//   - "request", written and fsynced before the request is built, with the
//     endpoint (scheme, host and path only: no userinfo or query), model,
//     purpose, byte count, sha256 of the exact body sent, redaction counts by
//     marker label, and payload_file. A failure here aborts the call before
//     any byte is sent.
//   - "result", after the reply, with a closed outcome enum, the HTTP status
//     and the tokens the provider reported. No error text, header or payload
//     byte is ever written to the log.
//
// The body itself is stored in <run>/payloads/<id>.payload (mode 0600, in a
// 0700 directory), so the user can check the hash and read what was sent.
//
// Seams for the rest of #3: consent (#82) gates Send before logRequest;
// Call.Payload and Call.Redactions come from the run's Redactor (#83);
// the token budget (#84) checks Call before sending and reads Usage.
package gateway
