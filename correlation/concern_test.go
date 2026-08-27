package correlation

import (
	"testing"

	"github.com/volknichtx/argus/model"
)

// Regression: counting every auth event as "authenticated" made a single failed
// password critical, because a failed ssh login always rides on an established
// connection to the listener it failed against. That both buried real break-ins
// and made the failure threshold below unreachable — no host ever survived long
// enough to accumulate three failures at a lower grade.
func TestFailedAuthOnAListenerIsNotTheAccessChain(t *testing.T) {
	tests := []struct {
		name    string
		auth    []model.AuthEventLog
		want    Concern
		because string
	}{
		{
			name:    "one failure while connected to the listener",
			auth:    []model.AuthEventLog{authEvent("203.0.113.9", 51000, "root", model.LoginFailed, false)},
			want:    ConcernElevated,
			because: "reaching a listener is elevated; failing to get in is not a break-in",
		},
		{
			name: "two failures stay below the cluster threshold",
			auth: []model.AuthEventLog{
				authEvent("203.0.113.9", 51000, "root", model.LoginFailed, false),
				authEvent("203.0.113.9", 51001, "root", model.LoginFailed, false),
			},
			want:    ConcernElevated,
			because: "two failures are a mistyped password",
		},
		{
			name: "the cluster threshold is reachable again",
			auth: []model.AuthEventLog{
				authEvent("203.0.113.9", 51000, "root", model.LoginFailed, false),
				authEvent("203.0.113.9", 51001, "root", model.LoginFailed, false),
				authEvent("203.0.113.9", 51002, "root", model.LoginFailed, false),
			},
			want:    ConcernCritical,
			because: "three failures from one address is someone trying",
		},
		{
			name:    "one success closes the chain",
			auth:    []model.AuthEventLog{authEvent("203.0.113.9", 51000, "root", model.LoginSuccess, true)},
			want:    ConcernCritical,
			because: "reached a listener and got in",
		},
		{
			name: "a success among failures still closes the chain",
			auth: []model.AuthEventLog{
				authEvent("203.0.113.9", 51000, "root", model.LoginFailed, false),
				authEvent("203.0.113.9", 51001, "root", model.LoginSuccess, true),
			},
			want:    ConcernCritical,
			because: "the failures before it are how a break-in looks",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hosts := Correlate(
				testPorts(),
				[]model.Connection{conn("10.0.0.10", "22", "203.0.113.9", "51000")},
				nil,
				tc.auth,
			)

			host := findHost(t, hosts, "203.0.113.9")

			if host.Concern != tc.want {
				t.Errorf("concern = %v, want %v: %s", host.Concern, tc.want, tc.because)
			}
		})
	}
}

// A listener on one protocol says nothing about the other. Keying the listener
// set on the port number alone turned every TCP connection whose local port
// happened to match a UDP listener into an inbound one.
func TestDirectionIsProtocolAware(t *testing.T) {
	ports := []model.Port{
		{Protocol: "udp", Addr: "0.0.0.0", Port: "5353", State: "UNCONN", PID: -1},
		{Protocol: "tcp", Addr: "0.0.0.0", Port: "22", State: "LISTEN", PID: -1},
	}

	listeners := ListeningPorts(ports)

	tests := []struct {
		name string
		conn model.Connection
		want Direction
	}{
		{
			name: "tcp connection on a udp listener's port is outbound",
			conn: model.Connection{
				Protocol: "tcp", LocalAddr: "10.0.0.10", LocalPort: "5353",
				RemoteAddr: "198.51.100.26", RemotePort: "443",
			},
			want: DirectionOutbound,
		},
		{
			name: "udp traffic on the udp listener is inbound",
			conn: model.Connection{
				Protocol: "udp", LocalAddr: "10.0.0.10", LocalPort: "5353",
				RemoteAddr: "10.0.0.20", RemotePort: "5353",
			},
			want: DirectionInbound,
		},
		{
			name: "tcp connection on the tcp listener is inbound",
			conn: model.Connection{
				Protocol: "tcp", LocalAddr: "10.0.0.10", LocalPort: "22",
				RemoteAddr: "10.0.0.20", RemotePort: "64985",
			},
			want: DirectionInbound,
		},
		{
			name: "protocol case does not matter",
			conn: model.Connection{
				Protocol: "TCP", LocalAddr: "10.0.0.10", LocalPort: "22",
				RemoteAddr: "10.0.0.20", RemotePort: "64985",
			},
			want: DirectionInbound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DirectionFor(tc.conn, listeners); got != tc.want {
				t.Errorf("direction = %v, want %v", got, tc.want)
			}
		})
	}
}

// A listener without a port number is not a listener and must not create a
// key that every portless connection then matches.
func TestListenerSetIgnoresPortlessRows(t *testing.T) {
	listeners := ListeningPorts([]model.Port{
		{Protocol: "tcp", Addr: "0.0.0.0", Port: "", State: "LISTEN", PID: -1},
	})

	if len(listeners) != 0 {
		t.Fatalf("listeners = %v, want none", listeners)
	}

	got := DirectionFor(model.Connection{Protocol: "tcp", LocalPort: ""}, listeners)

	if got != DirectionOutbound {
		t.Errorf("direction = %v, want %v", got, DirectionOutbound)
	}
}

// The summary names the ports a host reached, and it reads as a list of
// numbers, so it has to be ordered as numbers.
func TestInboundPortsAreOrderedNumerically(t *testing.T) {
	ports := []model.Port{
		{Protocol: "tcp", Port: "9", State: "LISTEN", PID: -1},
		{Protocol: "tcp", Port: "80", State: "LISTEN", PID: -1},
		{Protocol: "tcp", Port: "443", State: "LISTEN", PID: -1},
		{Protocol: "tcp", Port: "8080", State: "LISTEN", PID: -1},
	}

	hosts := Correlate(
		ports,
		[]model.Connection{
			conn("10.0.0.10", "443", "203.0.113.9", "51000"),
			conn("10.0.0.10", "80", "203.0.113.9", "51001"),
			conn("10.0.0.10", "8080", "203.0.113.9", "51002"),
			conn("10.0.0.10", "9", "203.0.113.9", "51003"),
			// A repeat must not produce a duplicate entry.
			conn("10.0.0.10", "80", "203.0.113.9", "51004"),
		},
		nil,
		nil,
	)

	host := findHost(t, hosts, "203.0.113.9")

	want := []string{"9", "80", "443", "8080"}
	got := host.InboundPorts()

	if len(got) != len(want) {
		t.Fatalf("inbound ports = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("inbound ports = %v, want %v", got, want)
		}
	}
}

// Ports are text, so the ordering has to stay total even for values that are
// not numbers at all.
func TestLessPortOrdersNumbersBeforeText(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "numbers compare numerically", a: "9", b: "80", want: true},
		{name: "and the other way round", a: "80", b: "9", want: false},
		{name: "a number sorts before a non-number", a: "22", b: "unknown", want: true},
		{name: "a non-number sorts after a number", a: "unknown", b: "22", want: false},
		{name: "two non-numbers compare as text", a: "alpha", b: "beta", want: true},
		{name: "equal values are not less", a: "22", b: "22", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lessPort(tc.a, tc.b); got != tc.want {
				t.Errorf("lessPort(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
