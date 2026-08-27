package netutil

import (
	"net"
	"strings"
)

// SplitSocketAddressZone separates an optional interface/zone suffix from an
// address stored in a socket model.
//
// Examples:
//
//	10.0.0.10%eno1 -> 10.0.0.10, eno1
//	fe80::1234%eno1     -> fe80::1234, eno1
//	10.0.0.10      -> 10.0.0.10, ""
//
// The original model value is intentionally left untouched so the view can
// still display all information emitted by ss.
func SplitSocketAddressZone(addr string) (host, zone string) {
	zoneIndex := strings.LastIndex(addr, "%")
	if zoneIndex == -1 {
		return addr, ""
	}

	return addr[:zoneIndex], addr[zoneIndex+1:]
}

// ParseIPFromSocketAddress converts a socket-model address into a net.IP for
// semantic operations such as cross-panel IP correlation.
//
// Any interface/zone suffix is stripped only for IP parsing. Use
// SplitSocketAddressZone when the zone itself is also relevant.
func ParseIPFromSocketAddress(addr string) net.IP {
	host, _ := SplitSocketAddressZone(addr)
	return net.ParseIP(host)
}

// IsPublicIP reports whether an address is routable on the public internet, and
// therefore foreign to this machine and its local network.
//
// This is the single definition of "public" shared by the correlation engine and
// the view; keeping two copies would let them drift apart and disagree about
// which hosts are worth flagging.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	switch {
	case ip.IsLoopback(),
		ip.IsUnspecified(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return false

	default:
		return true
	}
}

// IsRemoteHost reports whether an address belongs to some other machine: it must
// parse as an IP and must not be this host's own loopback.
//
// Used to tell a genuinely remote session or peer from a local one. Note that a
// non-IP value (who's "local", ":0", a tmux pane, a resolved hostname) is not
// remote — it cannot be correlated by IP at all.
func IsRemoteHost(addr string) bool {
	ip := ParseIPFromSocketAddress(addr)

	return ip != nil && !ip.IsLoopback()
}
