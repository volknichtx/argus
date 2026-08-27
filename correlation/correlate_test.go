package correlation

import (
	"net"
	"testing"
	"time"

	"github.com/volknichtx/argus/model"
)

// Listeners taken from the real dashboard: sshd on 22, appserver on 11434.
func testPorts() []model.Port {
	return []model.Port{
		{Protocol: "tcp", Addr: "0.0.0.0", Port: "22", State: "LISTEN", PID: -1},
		{Protocol: "tcp", Addr: "::", Port: "22", State: "LISTEN", PID: -1},
		{Protocol: "tcp", Addr: "127.0.0.1", Port: "11434", State: "LISTEN", PID: -1},
	}
}

func conn(localAddr, localPort, remoteAddr, remotePort string) model.Connection {
	return model.Connection{
		Protocol:   "tcp",
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		RemotePort: remotePort,
		State:      "ESTAB",
		PID:        -1,
		Process:    "undefined",
	}
}

func authEvent(source string, port int, user string, eventType model.AuthEventType, success bool) model.AuthEventLog {
	return model.AuthEventLog{
		Timestamp:  time.Date(2026, 8, 26, 14, 32, 37, 0, time.UTC),
		Service:    "sshd",
		EventType:  eventType,
		User:       user,
		SourceIP:   net.ParseIP(source),
		SourcePort: port,
		Success:    success,
	}
}

func findHost(t *testing.T, hosts []CorrelatedHost, address string) CorrelatedHost {
	t.Helper()

	for _, host := range hosts {
		if host.Address == address {
			return host
		}
	}

	t.Fatalf("host %q not correlated; got %v", address, addresses(hosts))

	return CorrelatedHost{}
}

func addresses(hosts []CorrelatedHost) []string {
	out := make([]string, 0, len(hosts))

	for _, host := range hosts {
		out = append(out, host.Address)
	}

	return out
}

// The headline case: one remote address that connected to our SSH listener,
// authenticated successfully and holds a live session. All three signals must
// land on a single host.
func TestCorrelateFullAccessChain(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{conn("10.0.0.10", "22", "10.0.0.20", "64985")},
		[]model.UserSession{{User: "alice", TTY: "pts/2", PID: 5832, Source: "10.0.0.20"}},
		[]model.AuthEventLog{authEvent("10.0.0.20", 64985, "alice", model.LoginSuccess, true)},
	)

	host := findHost(t, hosts, "10.0.0.20")

	if got := host.InboundCount(); got != 1 {
		t.Errorf("inbound = %d, want 1", got)
	}

	if got := host.OutboundCount(); got != 0 {
		t.Errorf("outbound = %d, want 0", got)
	}

	if got := len(host.Sessions); got != 1 {
		t.Errorf("sessions = %d, want 1", got)
	}

	if got := host.AuthSuccessCount(); got != 1 {
		t.Errorf("auth successes = %d, want 1", got)
	}

	if got, want := host.Users(), []string{"alice"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("users = %v, want %v", got, want)
	}

	if got := host.InboundPorts(); len(got) != 1 || got[0] != "22" {
		t.Errorf("inbound ports = %v, want [22]", got)
	}

	// Reached a listener and authenticated: the full access chain, and critical
	// even though the peer is on the LAN rather than the public internet.
	if got, want := host.Concern, ConcernCritical; got != want {
		t.Errorf("concern = %v, want %v", got, want)
	}
}

// A public address that both reached a listener and authenticated is the full
// break-in chain and must be critical.
func TestCorrelatePublicInboundWithAuthIsCritical(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{conn("10.0.0.10", "22", "203.0.113.9", "51000")},
		nil,
		[]model.AuthEventLog{authEvent("203.0.113.9", 51000, "root", model.LoginSuccess, true)},
	)

	host := findHost(t, hosts, "203.0.113.9")

	if got, want := host.Concern, ConcernCritical; got != want {
		t.Errorf("concern = %v, want %v", got, want)
	}
}

// Ordinary browsing must not light up: outbound HTTPS to a public host stays normal.
func TestCorrelateOutboundOnlyIsNormal(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{conn("10.0.0.10", "45192", "198.51.100.26", "443")},
		nil,
		nil,
	)

	host := findHost(t, hosts, "198.51.100.26")

	if got := host.OutboundCount(); got != 1 {
		t.Errorf("outbound = %d, want 1", got)
	}

	if got := host.InboundCount(); got != 0 {
		t.Errorf("inbound = %d, want 0", got)
	}

	if got, want := host.Concern, ConcernNormal; got != want {
		t.Errorf("concern = %v, want %v", got, want)
	}
}

// The normalization lynchpin: zone-suffixed and plain forms of one address are
// one host, not two.
func TestCorrelateNormalizesZoneSuffixes(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{
			conn("10.0.0.10%eno1", "22", "10.0.0.20%eno1", "64985"),
			conn("10.0.0.10", "22", "10.0.0.20", "64986"),
		},
		[]model.UserSession{{User: "alice", Source: "10.0.0.20%eno1", PID: -1}},
		nil,
	)

	if got := len(hosts); got != 1 {
		t.Fatalf("correlated %d hosts, want 1: %v", got, addresses(hosts))
	}

	host := hosts[0]

	if host.Address != "10.0.0.20" {
		t.Errorf("address = %q, want the normalized form", host.Address)
	}

	if got := len(host.Connections); got != 2 {
		t.Errorf("connections = %d, want 2 collapsed onto one host", got)
	}

	if got := len(host.Sessions); got != 1 {
		t.Errorf("sessions = %d, want 1", got)
	}
}

// An IPv6 peer must correlate the same way, including between an auth event's
// already-parsed net.IP and a connection's textual address.
func TestCorrelateNormalizesIPv6AcrossSources(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{conn("2001:db8:1::1", "22", "2001:db8:4:0::10", "443")},
		nil,
		[]model.AuthEventLog{authEvent("2001:db8:4::10", 443, "root", model.LoginFailed, false)},
	)

	if got := len(hosts); got != 1 {
		t.Fatalf("correlated %d hosts, want 1: %v", got, addresses(hosts))
	}

	host := hosts[0]

	if got := len(host.Connections); got != 1 {
		t.Errorf("connections = %d, want 1", got)
	}

	if got := len(host.AuthEvents); got != 1 {
		t.Errorf("auth events = %d, want 1 joined onto the same host", got)
	}
}

func TestDirectionHeuristic(t *testing.T) {
	tests := []struct {
		name      string
		conn      model.Connection
		want      Direction
		knownFlaw bool
	}{
		{
			name: "peer reached our ssh listener",
			conn: conn("10.0.0.10", "22", "10.0.0.20", "64985"),
			want: DirectionInbound,
		},
		{
			name: "we opened https to a public host",
			conn: conn("10.0.0.10", "45192", "198.51.100.26", "443"),
			want: DirectionOutbound,
		},
		{
			name: "loopback client to our appserver listener",
			conn: conn("127.0.0.1", "11434", "127.0.0.1", "50102"),
			want: DirectionInbound,
		},
		{
			// Documented limitation: the ephemeral source port the kernel
			// picked happens to equal one of our listening ports, so this
			// outbound connection is misread as inbound. Correcting it needs
			// TCP-state inspection, which is out of scope.
			name:      "ephemeral source port collides with a listener",
			conn:      conn("10.0.0.10", "11434", "198.51.100.26", "443"),
			want:      DirectionInbound,
			knownFlaw: true,
		},
	}

	listeners := ListeningPorts(testPorts())

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DirectionFor(tc.conn, listeners)

			if got != tc.want {
				t.Errorf("direction = %v, want %v", got, tc.want)
			}

			if tc.knownFlaw && got == DirectionOutbound {
				t.Log("the ephemeral-port collision now resolves correctly; " +
					"the documented limitation can be removed")
			}
		})
	}
}

// Loopback is this machine talking to itself and must never raise an alarm,
// whatever the signals look like. Regression for a false positive that ranked
// our own ssh tests above a host that had actually got in.
func TestLoopbackIsNeverAlarming(t *testing.T) {
	var cluster []model.AuthEventLog

	for i := 0; i < failedAuthCluster+2; i++ {
		cluster = append(cluster, authEvent("::1", 50956+i, "nosuchuser", model.InvalidUser, false))
	}

	tests := []struct {
		name        string
		address     string
		connections []model.Connection
		sessions    []model.UserSession
		auth        []model.AuthEventLog
	}{
		{
			name:    "failed auth cluster from ::1",
			address: "::1",
			auth:    cluster,
		},
		{
			name:        "inbound connection from loopback",
			address:     "127.0.0.1",
			connections: []model.Connection{conn("127.0.0.1", "22", "127.0.0.1", "50102")},
		},
		{
			name:     "local session recorded as ::1",
			address:  "::1",
			sessions: []model.UserSession{{User: "alice", TTY: "pts/5", Source: "::1", PID: 827621}},
		},
		{
			// Even the full chain: a local ssh round trip is not a break-in.
			name:        "inbound plus successful auth from loopback",
			address:     "::1",
			connections: []model.Connection{conn("::1", "22", "::1", "44622")},
			auth: []model.AuthEventLog{
				authEvent("::1", 44622, "alice", model.LoginSuccess, true),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hosts := Correlate(testPorts(), tc.connections, tc.sessions, tc.auth)
			host := findHost(t, hosts, tc.address)

			if host.Concern != ConcernNormal {
				t.Errorf("concern = %v, want %v: loopback is not an attack surface",
					host.Concern, ConcernNormal)
			}
		})
	}
}

// The access chain must be critical regardless of which side of the router the
// peer is on: lateral movement arrives from a private address.
func TestAccessChainIsCriticalFromLanAndInternet(t *testing.T) {
	peers := []struct {
		name string
		addr string
	}{
		{name: "public peer", addr: "203.0.113.9"},
		{name: "lan peer", addr: "10.0.0.20"},
		{name: "other private range", addr: "10.0.0.5"},
	}

	for _, peer := range peers {
		t.Run(peer.name, func(t *testing.T) {
			hosts := Correlate(
				testPorts(),
				[]model.Connection{conn("10.0.0.10", "22", peer.addr, "51000")},
				nil,
				[]model.AuthEventLog{authEvent(peer.addr, 51000, "root", model.LoginSuccess, true)},
			)

			host := findHost(t, hosts, peer.addr)

			if host.Concern != ConcernCritical {
				t.Errorf("concern = %v, want %v", host.Concern, ConcernCritical)
			}
		})
	}
}

// Within one concern level, a peer from the public internet outranks a LAN peer.
func TestPublicPeersOutrankPrivateAtSameConcern(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{
			conn("10.0.0.10", "22", "10.0.0.20", "64985"),
			conn("10.0.0.10", "22", "203.0.113.9", "51000"),
		},
		nil,
		nil,
	)

	got := addresses(hosts)
	want := []string{"203.0.113.9", "10.0.0.20"}

	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// Repeated failures from one address are critical even without a session or a
// successful login.
func TestFailedAuthClusterIsCritical(t *testing.T) {
	var events []model.AuthEventLog

	for i := 0; i < failedAuthCluster; i++ {
		events = append(events, authEvent("203.0.113.9", 51000+i, "admin", model.InvalidUser, false))
	}

	hosts := Correlate(testPorts(), nil, nil, events)
	host := findHost(t, hosts, "203.0.113.9")

	if got := host.FailedAuthCount(); got != failedAuthCluster {
		t.Errorf("failed auth = %d, want %d", got, failedAuthCluster)
	}

	if got, want := host.Concern, ConcernCritical; got != want {
		t.Errorf("concern = %v, want %v", got, want)
	}

	// One below the threshold must not trip it.
	hosts = Correlate(testPorts(), nil, nil, events[:failedAuthCluster-1])
	host = findHost(t, hosts, "203.0.113.9")

	if got, want := host.Concern, ConcernNormal; got != want {
		t.Errorf("concern below threshold = %v, want %v", got, want)
	}
}

// A host is never dropped for missing signals.
func TestCorrelatePartialSignals(t *testing.T) {
	tests := []struct {
		name        string
		connections []model.Connection
		sessions    []model.UserSession
		auth        []model.AuthEventLog
		address     string
		wantConcern Concern
	}{
		{
			name:        "session only from a remote host",
			sessions:    []model.UserSession{{User: "alice", Source: "10.0.0.20", PID: -1}},
			address:     "10.0.0.20",
			wantConcern: ConcernElevated,
		},
		{
			name:        "auth only, single failure",
			auth:        []model.AuthEventLog{authEvent("203.0.113.9", 51000, "admin", model.InvalidUser, false)},
			address:     "203.0.113.9",
			wantConcern: ConcernNormal,
		},
		{
			name:        "connection only, outbound",
			connections: []model.Connection{conn("10.0.0.10", "45192", "192.0.2.8", "443")},
			address:     "192.0.2.8",
			wantConcern: ConcernNormal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hosts := Correlate(testPorts(), tc.connections, tc.sessions, tc.auth)
			host := findHost(t, hosts, tc.address)

			if host.Concern != tc.wantConcern {
				t.Errorf("concern = %v, want %v", host.Concern, tc.wantConcern)
			}
		})
	}
}

// Which who(1) source formats reach the join, and which drop out. The collector
// already strips the parentheses who wraps the field in, so the ordinary formats
// arrive parseable; this pins down exactly where the boundary sits.
func TestSessionSourceFormatsThatJoin(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		wantJoin  bool
		wantHost  string
		rationale string
	}{
		{
			name:     "ipv4 as sshd records it in utmp",
			source:   "10.0.0.20",
			wantJoin: true,
			wantHost: "10.0.0.20",
		},
		{
			name:     "ipv6 loopback from a local ssh",
			source:   "::1",
			wantJoin: true,
			wantHost: "::1",
		},
		{
			name:     "zone-suffixed address",
			source:   "fe80::1%eno1",
			wantJoin: true,
			wantHost: "fe80::1",
		},
		{
			name:      "who's placeholder for a local login",
			source:    "local",
			rationale: "not an address at all",
		},
		{
			name:      "x display",
			source:    ":0",
			rationale: "display spec, not an address",
		},
		{
			name:      "tmux pane",
			source:    "tmux(523831).%0",
			rationale: "multiplexer pane, not an address",
		},
		{
			// The real gap: sshd with UseDNS, or who --lookup, records a name.
			// It cannot be joined without DNS I/O, which a pure function must
			// not do, so the session drops out.
			name:      "reverse-resolved hostname",
			source:    "workstation.lan",
			rationale: "hostname, would need DNS to resolve back to an address",
		},
		{
			name:      "hostname with x display",
			source:    "workstation.lan:S.0",
			rationale: "hostname plus display",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hosts := Correlate(
				testPorts(),
				nil,
				[]model.UserSession{{User: "alice", TTY: "pts/2", Source: tc.source, PID: 5832}},
				nil,
			)

			if !tc.wantJoin {
				if len(hosts) != 0 {
					t.Errorf("source %q produced host %v, want none (%s)",
						tc.source, addresses(hosts), tc.rationale)
				}

				return
			}

			host := findHost(t, hosts, tc.wantHost)

			if len(host.Sessions) != 1 {
				t.Errorf("source %q joined %d sessions, want 1", tc.source, len(host.Sessions))
			}
		})
	}
}

// Local auth events carry no source IP, so they cannot participate in an IP
// join. The auth pane still lists them; the correlation deliberately does not.
func TestLocalAuthEventsAreNotCorrelated(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		nil,
		nil,
		[]model.AuthEventLog{
			{Timestamp: time.Now(), Service: "sudo", EventType: model.SudoSuccess, User: "alice", Success: true},
			{Timestamp: time.Now(), Service: "su", EventType: model.SuSuccess, User: "root", Success: true},
			{Timestamp: time.Now(), Service: "sshd", EventType: model.InvalidUser, User: "", Success: false},
		},
	)

	if len(hosts) != 0 {
		t.Errorf("correlated %v from events with no source IP, want none", addresses(hosts))
	}
}

// Sources that carry no usable IP must be skipped, not guessed at.
func TestCorrelateSkipsNonAddressableSources(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		nil,
		[]model.UserSession{
			{User: "alice", TTY: "tty1", Source: "local", PID: 1291},
			{User: "alice", TTY: "pts/4", Source: "tmux(523831).%0", PID: 523831},
			{User: "alice", TTY: "pts/5", Source: ":0", PID: 900},
		},
		[]model.AuthEventLog{
			{Timestamp: time.Now(), Service: "sudo", EventType: model.SudoSuccess, User: "alice", Success: true},
		},
	)

	if len(hosts) != 0 {
		t.Errorf("correlated %v, want none: no source carries an IP", addresses(hosts))
	}
}

// Ordering must be deterministic: most concerning first, then by address.
func TestCorrelateOrdering(t *testing.T) {
	var cluster []model.AuthEventLog

	for i := 0; i < failedAuthCluster; i++ {
		cluster = append(cluster, authEvent("198.51.100.7", 40000+i, "root", model.LoginFailed, false))
	}

	hosts := Correlate(
		testPorts(),
		[]model.Connection{
			conn("10.0.0.10", "45192", "198.51.100.26", "443"),
			conn("10.0.0.10", "45193", "192.0.2.8", "443"),
			conn("10.0.0.10", "22", "10.0.0.20", "64985"),
		},
		nil,
		cluster,
	)

	want := []string{
		"198.51.100.7", // critical: failed-auth cluster
		"10.0.0.20",    // elevated: inbound on a listener
		"192.0.2.8",    // normal, sorts first numerically
		"198.51.100.26",
	}

	got := addresses(hosts)

	if len(got) != len(want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// The same inputs must always produce the same output.
func TestCorrelateIsDeterministic(t *testing.T) {
	ports := testPorts()
	connections := []model.Connection{
		conn("10.0.0.10", "22", "10.0.0.20", "64985"),
		conn("10.0.0.10", "45192", "198.51.100.26", "443"),
		conn("10.0.0.10", "45193", "192.0.2.8", "443"),
		conn("10.0.0.10", "45194", "192.0.2.1", "443"),
	}

	first := addresses(Correlate(ports, connections, nil, nil))

	for i := 0; i < 20; i++ {
		got := addresses(Correlate(ports, connections, nil, nil))

		for j := range first {
			if got[j] != first[j] {
				t.Fatalf("run %d produced %v, first run produced %v", i, got, first)
			}
		}
	}
}
