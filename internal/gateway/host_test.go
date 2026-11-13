package gateway

import (
	"errors"
	"net/netip"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "API.Example.COM.", want: "api.example.com"},
		{in: "localhost", want: "localhost"},
		{in: "::ffff:127.0.0.1", want: "127.0.0.1"},
		{in: "::1", want: "::1"},
		{in: "xn--bcher-kva.example", want: "xn--bcher-kva.example"},
		{in: "", wantErr: true},
		{in: "2130706433", wantErr: true},        // decimal 127.0.0.1
		{in: "0x7f000001", wantErr: true},        // hex
		{in: "0x7f.0.0.1", wantErr: true},        // hex octet
		{in: "0177.0.0.1", wantErr: true},        // octal
		{in: "127.1", wantErr: true},             // short form
		{in: "127.0.0.1.", want: "127.0.0.1"},    // trailing dot on a literal
		{in: "fe80::1%eth0", wantErr: true},      // zone
		{in: "local_host", wantErr: true},        // underscore
		{in: "-evil.example", wantErr: true},     // leading hyphen
		{in: "evil..example", wantErr: true},     // empty label
		{in: "evil.example/x", wantErr: true},    // path character
		{in: "bücher.example", wantErr: true},    // raw unicode, want punycode
		{in: "a.b.c.d.e.f.g.123", wantErr: true}, // numeric last label
	}
	for _, tt := range tests {
		got, err := normalizeHost(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("normalizeHost(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil && !errors.Is(err, ErrInvalidHost) {
			t.Errorf("normalizeHost(%q) err = %v, want ErrInvalidHost", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"127.255.10.9", true},
		{"::1", true},
		{"localhost.attacker.com", false},
		{"localhost.localdomain", false},
		{"attacker-localhost", false},
		{"127.0.0.1.nip.io", false},
		{"0.0.0.0", false},
		{"::", false},
		{"10.0.0.1", false},
		{"128.0.0.1", false},
	}
	for _, tt := range tests {
		if got := isLoopbackHost(tt.host); got != tt.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		entry   string
		want    endpoint
		wantErr bool
	}{
		{entry: "api.example.com", want: endpoint{"api.example.com", ""}},
		{entry: "Api.Example.com:8443", want: endpoint{"api.example.com", "8443"}},
		{entry: "localhost:11434", want: endpoint{"localhost", "11434"}},
		{entry: "::1", want: endpoint{"::1", ""}},
		{entry: "[::1]", want: endpoint{"::1", ""}},
		{entry: "[::1]:8080", want: endpoint{"::1", "8080"}},
		{entry: "10.0.0.5:8443", want: endpoint{"10.0.0.5", "8443"}},
		{entry: "example.com:0", wantErr: true},
		{entry: "example.com:65536", wantErr: true},
		{entry: "example.com:0443", wantErr: true},
		{entry: "example.com:", wantErr: true},
		{entry: "2130706433", wantErr: true},
		{entry: "[::1", wantErr: true},
		{entry: "", wantErr: true},
	}
	for _, tt := range tests {
		a, err := parseAllowlist([]string{tt.entry})
		if (err != nil) != tt.wantErr {
			t.Errorf("parseAllowlist(%q) err = %v, wantErr %v", tt.entry, err, tt.wantErr)
			continue
		}
		if err == nil && !a.endpoints[tt.want] {
			t.Errorf("parseAllowlist(%q) = %v, want entry %v", tt.entry, a.endpoints, tt.want)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", true},
		{"198.51.100.7", true},
		{"2606:4700::1111", true},
		{"64:ff9b::5db8:d822", true}, // NAT64 of a public IPv4
		{"169.254.169.254", false},   // cloud metadata
		{"fd00:ec2::254", false},     // AWS IPv6 metadata
		{"127.0.0.1", false},
		{"127.8.9.10", false},
		{"::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"::ffff:10.0.0.1", false}, // IPv4-mapped private
		{"::ffff:169.254.169.254", false},
		{"::7f00:1", false},             // IPv4-compatible loopback
		{"64:ff9b::a9fe:a9fe", false},   // NAT64 of 169.254.169.254
		{"64:ff9b::7f00:1", false},      // NAT64 of 127.0.0.1
		{"::ffff:0:7f00:1", false},      // SIIT of 127.0.0.1
		{"::ffff:0:a9fe:a9fe", false},   // SIIT of 169.254.169.254
		{"::ffff:0:a00:1", false},       // SIIT of 10.0.0.1
		{"::ffff:0:5db8:d822", true},    // SIIT of a public IPv4
		{"64:ff9b:1::a9fe:a9fe", false}, // local-use NAT64
		{"168.63.129.16", false},        // Azure WireServer
		{"2002:7f00:1::", false},        // 6to4 of 127.0.0.1
		{"fe80::1", false},
		{"fc00::1", false},
		{"ff02::1", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
	}
	for _, tt := range tests {
		if got := publicAddr(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("publicAddr(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
