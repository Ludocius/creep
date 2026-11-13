package gateway

import "net/netip"

// refusedPrefixes are ranges a DNS answer for a public model endpoint has no
// reason to contain. Returning one is how DNS rebinding and SSRF reach the
// local machine, the LAN or a cloud metadata service (169.254.169.254,
// fd00:ec2::254). Prefixes that embed an IPv4 address in a way we do not
// decode (6to4, Teredo, IPv4-compatible) are refused whole.
var refusedPrefixes = mustPrefixes(
	"0.0.0.0/8",      // "this network"; 0.0.0.0 reaches local listeners
	"10.0.0.0/8",     // private
	"100.64.0.0/10",  // carrier-grade NAT
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local, cloud metadata
	"172.16.0.0/12",  // private
	"192.0.0.0/24",   // IETF protocol assignments
	"192.168.0.0/16", // private
	"198.18.0.0/15",  // benchmarking
	"224.0.0.0/3",    // multicast, reserved, broadcast
	"::/96",          // unspecified, loopback, IPv4-compatible
	"100::/64",       // discard
	"2001::/32",      // Teredo
	"2002::/16",      // 6to4
	"64:ff9b:1::/48", // local-use NAT64
	"fc00::/7",       // unique local
	"fe80::/10",      // link-local
	"ff00::/8",       // multicast
	"fec0::/10",      // deprecated site-local
)

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// publicAddr reports whether a resolved address may be dialed for a DNS name
// that the allowlist does not pin to an explicit IP.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	if nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	for _, p := range refusedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
