// Package correlation joins the four collected data sets into per-host units.
//
// It is a pure function of its inputs: no I/O, no UI, no shared state. The view
// is a projection of what Correlate returns, so a wrong answer is always a bug
// in here and is fixed here, never in the rendering layer.
package correlation

import (
	"bytes"
	"net"
	"sort"
	"strings"

	"github.com/volknichtx/argus/internal/netutil"
	"github.com/volknichtx/argus/model"
)

// failedAuthCluster is how many failed authentications from one host it takes to
// treat that host as critical on its own. Two failures are a fat-fingered
// password; three or more from the same address is someone trying.
const failedAuthCluster = 3

// Direction says which side opened a connection, derived from whether the local
// port is one this machine listens on.
type Direction int

const (
	DirectionOutbound Direction = iota
	DirectionInbound
)

func (d Direction) String() string {
	if d == DirectionInbound {
		return "inbound"
	}

	return "outbound"
}

// Concern grades how much attention a host deserves. Ordered so that a higher
// value is more concerning, which is also the sort order of the result.
type Concern int

const (
	ConcernNormal Concern = iota
	ConcernElevated
	ConcernCritical
)

func (c Concern) String() string {
	switch c {
	case ConcernCritical:
		return "critical"
	case ConcernElevated:
		return "elevated"
	default:
		return "normal"
	}
}

// HostConnection is a connection annotated with the direction we inferred.
type HostConnection struct {
	model.Connection
	Direction Direction
}

// CorrelatedHost is everything the four sources know about one remote address.
type CorrelatedHost struct {
	// IP is the parsed, normalized address; Address is its canonical text form
	// and the key the sources were joined on.
	IP      net.IP
	Address string

	Connections []HostConnection
	Sessions    []model.UserSession
	AuthEvents  []model.AuthEventLog

	Concern Concern
}

// Correlate groups connections, sessions and auth events by their normalized
// remote address and grades each resulting host.
//
// Sources that carry no usable IP are skipped rather than guessed at: a session
// whose origin who(1) reports as "local", ":0" or a tmux pane cannot be tied to
// a remote host, and an auth event without a source IP is local by definition.
//
// Three consequences of joining on IP alone are worth knowing:
//
//   - A local auth event carries no source IP, so an IP join alone cannot place
//     it. Privilege changes are the exception: su and sudo record the login
//     session they ran in, and a session that logind knows carries the address
//     it was opened from, so the chain login → escalation resolves exactly.
//     Anything else local — a console login, a sudo from a session logind does
//     not know — has no handle at all and is dropped.
//   - A session whose origin utmp recorded as a hostname rather than an address
//     — sshd with UseDNS enabled, or who(1) run with --lookup — does not parse
//     and drops out of the join silently. The collector strips who's parentheses,
//     so the common formats do arrive parseable; a resolving step would be the
//     fix, but it means DNS I/O and does not belong in a pure function.
//   - Loopback activity is bucketed under ::1 or 127.0.0.1 when it carries an
//     address and dropped when it does not, so localhost events are split across
//     both fates. Since loopback is never graded above normal, neither fate
//     raises an alarm and the inconsistency stays cosmetic.
func Correlate(
	ports []model.Port,
	connections []model.Connection,
	sessions []model.UserSession,
	authEvents []model.AuthEventLog,
) []CorrelatedHost {
	listeners := ListeningPorts(ports)

	hosts := make(map[string]*CorrelatedHost)

	for _, conn := range connections {
		host := hostFor(hosts, conn.RemoteAddr)
		if host == nil {
			continue
		}

		host.Connections = append(host.Connections, HostConnection{
			Connection: conn,
			Direction:  DirectionFor(conn, listeners),
		})
	}

	for _, session := range sessions {
		host := hostFor(hosts, session.Source)
		if host == nil {
			continue
		}

		host.Sessions = append(host.Sessions, session)
	}

	origins := sessionOrigins(sessions)

	for _, event := range authEvents {
		address, ok := originOf(event, origins)
		if !ok {
			continue
		}

		host := hostFor(hosts, address)
		if host == nil {
			continue
		}

		host.AuthEvents = append(host.AuthEvents, event)
	}

	result := make([]CorrelatedHost, 0, len(hosts))

	for _, host := range hosts {
		host.Concern = concernFor(*host)
		result = append(result, *host)
	}

	sortHosts(result)

	return result
}

// hostFor returns the host bucket for an address, creating it on first use.
// Returns nil when the address does not parse as an IP, which is how
// non-correlatable sources are dropped.
func hostFor(hosts map[string]*CorrelatedHost, addr string) *CorrelatedHost {
	ip := netutil.ParseIPFromSocketAddress(addr)
	if ip == nil {
		return nil
	}

	// The canonical text form is the join key, so "10.0.0.20%eno1",
	// "10.0.0.20" and an already-parsed net.IP all land in one bucket.
	key := ip.String()

	if host, ok := hosts[key]; ok {
		return host
	}

	host := &CorrelatedHost{IP: ip, Address: key}
	hosts[key] = host

	return host
}

// listenerKey identifies a listening socket by protocol as well as port.
//
// Keying on the port number alone let a UDP listener on 5353 turn every TCP
// connection whose local port happened to be 5353 into an inbound one — a
// listener the connection could never have reached.
type listenerKey struct {
	protocol string
	port     string
}

// originOf resolves the address an auth event came from.
//
// Most events carry one directly. A privilege change does not — su and sudo are
// local by nature — but it does carry the login session it ran in, and that
// session may have been opened from somewhere else. Following that link is what
// turns "someone became root" into "the host that logged in became root".
func originOf(event model.AuthEventLog, origins map[string]string) (string, bool) {
	if event.SourceIP != nil {
		return event.SourceIP.String(), true
	}

	if event.AuditSession == "" {
		return "", false
	}

	address, ok := origins[event.AuditSession]

	return address, ok
}

// sessionOrigins maps a login session identifier onto the address that session
// was opened from.
//
// Sessions without an identifier, without a remote origin, or sharing an
// identifier are left out. An ambiguous link here would attribute a privilege
// change to the wrong login, which is exactly the kind of fabricated finding
// this engine refuses to produce — a missed escalation is the cheaper mistake.
func sessionOrigins(sessions []model.UserSession) map[string]string {
	origins := make(map[string]string, len(sessions))
	ambiguous := make(map[string]bool)

	for _, session := range sessions {
		if session.ID == "" || !netutil.IsRemoteHost(session.Source) {
			continue
		}

		if existing, seen := origins[session.ID]; seen && existing != session.Source {
			ambiguous[session.ID] = true
			continue
		}

		origins[session.ID] = session.Source
	}

	for id := range ambiguous {
		delete(origins, id)
	}

	return origins
}

// ListenerSet is the set of sockets this machine accepts connections on.
type ListenerSet map[listenerKey]bool

// ListeningPorts builds the listener set used by the direction heuristic.
//
// Exported so the view can grade a single connection the same way the engine
// does, instead of keeping a second, drifting notion of what "inbound" means.
func ListeningPorts(ports []model.Port) ListenerSet {
	listeners := make(ListenerSet, len(ports))

	for _, port := range ports {
		if port.Port == "" {
			continue
		}

		listeners[socketKey(port.Protocol, port.Port)] = true
	}

	return listeners
}

// socketKey normalizes the protocol so "tcp", "TCP" and a padded variant all
// address the same listener.
func socketKey(protocol, port string) listenerKey {
	return listenerKey{
		protocol: strings.ToLower(strings.TrimSpace(protocol)),
		port:     port,
	}
}

// DirectionFor infers who opened a connection: if its local socket is one we
// listen on, the peer connected to us.
//
// Known limitation: the kernel may hand out an ephemeral source port that
// happens to equal one of our listening ports of the same protocol, and such an
// outbound connection is then misread as inbound. Distinguishing those properly
// needs TCP-state inspection, which is deliberately out of scope; the heuristic
// is right for every ordinary case and cheap.
func DirectionFor(conn model.Connection, listeners ListenerSet) Direction {
	if listeners[socketKey(conn.Protocol, conn.LocalPort)] {
		return DirectionInbound
	}

	return DirectionOutbound
}

// concernFor grades a host from the combination of its signals.
//
// Loopback is filtered out before any signal is weighed. This machine talking to
// itself is not an attack surface: an adversary who already holds local access
// is past everything this tool watches. Grading localhost would bury real
// findings under our own ssh tests, local services authenticating, and any
// daemon that retries a password — exactly the false positive that put a
// harmless "3 failed logins from ::1" above a host that actually got in.
//
// Note that the remaining levels deliberately do not care whether the peer is
// public or merely on the LAN. A compromised IoT device, a neighbour on the
// Wi-Fi or lateral movement from another machine all arrive from a private
// address, and "reached a listener and authenticated" is the same threat
// whichever side of the router it came from. Public peers still surface first,
// but through the ordering, not by making LAN peers unrankable.
func concernFor(host CorrelatedHost) Concern {
	if host.IP.IsLoopback() {
		return ConcernNormal
	}

	inbound := host.InboundCount() > 0

	switch {
	// Something authenticated successfully from off this machine: a login, or a
	// privilege change made from a session this host opened — an escalation is
	// an authentication too, so it lands here rather than needing a case of its
	// own. TestEscalationAloneIsCritical holds that guarantee.
	//
	// Whether the connection that carried it is still open does not change what
	// happened, so this deliberately does not require the host to still be
	// inbound: a short session that has since closed used to fall all the way
	// back to normal, ranking a successful break-in below three failed attempts.
	//
	// Only a *successful* authentication counts. Counting every auth event made
	// a single failed password critical, because a failed ssh login always
	// rides on an established connection to the listener it failed against —
	// which drowned real findings and made the threshold below unreachable.
	case host.AuthSuccessCount() > 0:
		return ConcernCritical

	// Repeated failures from one address, whether or not it got through.
	case host.FailedAuthCount() >= failedAuthCluster:
		return ConcernCritical

	case inbound:
		return ConcernElevated

	case len(host.Sessions) > 0:
		return ConcernElevated

	default:
		return ConcernNormal
	}
}

// sortHosts orders most concerning first; within one level a peer from the
// public internet outranks one from the local network, since the same chain of
// signals is worse coming from outside. Address order breaks the remaining ties
// so the view and the tests see a stable result.
func sortHosts(hosts []CorrelatedHost) {
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Concern != hosts[j].Concern {
			return hosts[i].Concern > hosts[j].Concern
		}

		iPublic, jPublic := netutil.IsPublicIP(hosts[i].IP), netutil.IsPublicIP(hosts[j].IP)
		if iPublic != jPublic {
			return iPublic
		}

		return bytes.Compare(hosts[i].IP.To16(), hosts[j].IP.To16()) < 0
	})
}
