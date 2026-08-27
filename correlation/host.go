package correlation

import (
	"sort"
	"strconv"
)

// The accessors below are what the view renders from. Keeping the counting here
// rather than in the view means the summary shown on screen and the concern
// grading are computed from the same numbers.

// InboundCount is how many of this host's connections reached one of our listeners.
func (h CorrelatedHost) InboundCount() int {
	return h.countConnections(DirectionInbound)
}

// OutboundCount is how many connections this machine opened to the host.
func (h CorrelatedHost) OutboundCount() int {
	return h.countConnections(DirectionOutbound)
}

func (h CorrelatedHost) countConnections(direction Direction) int {
	n := 0

	for _, conn := range h.Connections {
		if conn.Direction == direction {
			n++
		}
	}

	return n
}

// InboundPorts lists the local ports this host connected to, ascending and
// deduplicated, so the summary can name them ("in :22").
//
// Ports are numbers that ss hands over as text, so they are ordered as numbers:
// comparing the strings would put :443 ahead of :80 and leave :9 last.
func (h CorrelatedHost) InboundPorts() []string {
	seen := make(map[string]bool)
	ports := make([]string, 0, len(h.Connections))

	for _, conn := range h.Connections {
		if conn.Direction != DirectionInbound || seen[conn.LocalPort] {
			continue
		}

		seen[conn.LocalPort] = true
		ports = append(ports, conn.LocalPort)
	}

	sort.Slice(ports, func(i, j int) bool {
		return lessPort(ports[i], ports[j])
	})

	return ports
}

// lessPort orders two textual port numbers numerically. Anything that is not a
// number sorts after everything that is, and ties fall back to a string
// comparison, so the order stays total and the result deterministic.
func lessPort(a, b string) bool {
	numA, errA := strconv.Atoi(a)
	numB, errB := strconv.Atoi(b)

	switch {
	case errA == nil && errB == nil:
		return numA < numB
	case errA == nil:
		return true
	case errB == nil:
		return false
	default:
		return a < b
	}
}

// EscalationCount is how many times a session from this host became root.
//
// This is the signal the whole join exists for: su and sudo carry no address of
// their own, so without following the login session back to its origin an
// escalation is just an anonymous local event.
func (h CorrelatedHost) EscalationCount() int {
	n := 0

	for _, event := range h.AuthEvents {
		if event.IsEscalation() {
			n++
		}
	}

	return n
}

// LoginCount is how many times this host logged in successfully, as distinct
// from privilege changes made from inside a login it already held. Counting
// those here would report one ssh login that ran sudo twice as three logins.
func (h CorrelatedHost) LoginCount() int {
	n := 0

	for _, event := range h.AuthEvents {
		if event.Success && !event.IsPrivilegeChange() {
			n++
		}
	}

	return n
}

// AuthSuccessCount is how many authentications from this host succeeded.
func (h CorrelatedHost) AuthSuccessCount() int {
	n := 0

	for _, event := range h.AuthEvents {
		if event.Success {
			n++
		}
	}

	return n
}

// FailedAuthCount is how many authentications from this host failed.
func (h CorrelatedHost) FailedAuthCount() int {
	return len(h.AuthEvents) - h.AuthSuccessCount()
}

// Users are the account names this host is associated with, from both its live
// sessions and its auth events, deduplicated and sorted for a stable summary.
func (h CorrelatedHost) Users() []string {
	seen := make(map[string]bool)
	users := make([]string, 0, len(h.Sessions)+len(h.AuthEvents))

	add := func(user string) {
		if user == "" || seen[user] {
			return
		}

		seen[user] = true
		users = append(users, user)
	}

	for _, session := range h.Sessions {
		add(session.User)
	}

	for _, event := range h.AuthEvents {
		add(event.User)
	}

	sort.Strings(users)

	return users
}
