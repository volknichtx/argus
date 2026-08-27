package tui

import (
	"github.com/volknichtx/argus/correlation"
	"github.com/volknichtx/argus/internal/netutil"
	models "github.com/volknichtx/argus/model"
)

// Placeholder for values the collectors could not determine.
const unknownValue = "—"

// toneForListenAddr flags sockets that are reachable from outside the host.
func toneForListenAddr(port models.Port) tone {
	if port.Addr == "*" {
		return toneWarn
	}

	ip := netutil.ParseIPFromSocketAddress(port.Addr)
	if ip == nil {
		return toneDefault
	}

	switch {
	case ip.IsLoopback():
		// 127.0.0.1 / ::1
		return toneDefault

	case ip.IsUnspecified():
		// 0.0.0.0 / ::
		return toneWarn

	case ip.IsLinkLocalUnicast():
		// fe80::...
		return toneDefault

	case ip.IsPrivate():
		// 192.168.x.x
		// 10.x.x.x
		// 172.16.x.x - 172.31.x.x
		return toneDefault

	default:
		return toneWarn
	}
}

// toneForConnection grades an established connection by direction first and
// peer second — the same rule the correlation engine uses to assign concern, so
// the two panes never disagree about the same connection.
//
// Grading on "is the peer public?" alone was actively misleading: outbound HTTPS
// is what a workstation does all day, so nearly every row lit up as a warning
// while an inbound session on a listener — the one thing worth seeing — stayed
// plain.
func toneForConnection(conn models.Connection, direction correlation.Direction) tone {
	ip := netutil.ParseIPFromSocketAddress(conn.RemoteAddr)

	switch {
	case ip == nil:
		return toneMuted

	case ip.IsUnspecified():
		// 0.0.0.0 / :: as the peer of an established connection is anomalous
		// whatever the direction: a live connection always has a concrete peer.
		return toneDanger
	}

	if direction == correlation.DirectionInbound {
		if netutil.IsPublicIP(ip) {
			// Something on the internet reached one of our listeners.
			return toneDanger
		}

		// Reached a listener from the LAN or from this machine.
		return toneWarn
	}

	if netutil.IsPublicIP(ip) {
		// Ordinary outbound traffic: legible, but not an alarm.
		return toneDefault
	}

	// Local and LAN chatter.
	return toneMuted
}

func toneForEventType(eventType models.AuthEventType) tone {
	switch eventType {
	case models.LoginSuccess,
		models.SudoSuccess,
		models.SuSuccess:
		return toneOK

	case models.LoginFailed,
		models.SudoFailed,
		models.SuFailed:
		return toneDanger

	case models.InvalidUser:
		return toneWarn

	default:
		return toneDefault
	}
}

// valueOrUnknown keeps empty and placeholder values from shouting in the table.
func valueOrUnknown(value string) cell {
	if value == "" || value == "undefined" {
		return dim(unknownValue)
	}

	return txt(value)
}
