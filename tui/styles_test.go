package tui

import (
	"fmt"
	"testing"

	"github.com/volknichtx/argus/correlation"
	models "github.com/volknichtx/argus/model"
)

// Listening sockets: anything reachable from outside this host is flagged, and
// anything we cannot classify counts as reachable.
func TestToneForListenAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want tone
	}{
		{name: "wildcard", addr: "*", want: toneWarn},
		{name: "unspecified ipv4", addr: "0.0.0.0", want: toneWarn},
		{name: "unspecified ipv6", addr: "::", want: toneWarn},
		{name: "unspecified ipv4 with zone", addr: "0.0.0.0%virbr0", want: toneWarn},
		{name: "loopback ipv4", addr: "127.0.0.1", want: toneDefault},
		{name: "loopback ipv6", addr: "::1", want: toneDefault},
		{name: "private ipv4", addr: "10.1.0.1", want: toneDefault},
		{name: "link local ipv6 with zone", addr: "fe80::3%eno1", want: toneDefault},

		// The branch that matters in practice and never shows up in local
		// testing: an address we cannot place is treated as exposed.
		{name: "public ipv4", addr: "192.0.2.8", want: toneWarn},
		{name: "public ipv6", addr: "2001:db8:3::94eb", want: toneWarn},

		{name: "empty", addr: "", want: toneDefault},
		{name: "unparseable", addr: "not-an-ip", want: toneDefault},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toneForListenAddr(models.Port{Addr: tc.addr})

			if got != tc.want {
				t.Errorf("toneForListenAddr(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// Established connections are graded by direction first: reaching one of our
// listeners is the event, an outbound peer being public is just the internet.
func TestToneForConnection(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		direction correlation.Direction
		want      tone
	}{
		// Inbound: someone reached a port we listen on.
		{
			name:      "inbound from the internet",
			addr:      "203.0.113.9",
			direction: correlation.DirectionInbound,
			want:      toneDanger,
		},
		{
			name:      "inbound from the lan",
			addr:      "10.0.0.20",
			direction: correlation.DirectionInbound,
			want:      toneWarn,
		},
		{
			name:      "inbound from loopback",
			addr:      "::1",
			direction: correlation.DirectionInbound,
			want:      toneWarn,
		},

		// Outbound: what a workstation does all day. Must not shout.
		{
			name:      "outbound https to a public host",
			addr:      "198.51.100.26",
			direction: correlation.DirectionOutbound,
			want:      toneDefault,
		},
		{
			name:      "outbound ipv6 to a public host",
			addr:      "2001:db8:4::10",
			direction: correlation.DirectionOutbound,
			want:      toneDefault,
		},
		{
			name:      "outbound to the router",
			addr:      "10.0.0.1",
			direction: correlation.DirectionOutbound,
			want:      toneMuted,
		},
		{
			name:      "outbound to loopback",
			addr:      "127.0.0.1",
			direction: correlation.DirectionOutbound,
			want:      toneMuted,
		},

		// An established connection always has a concrete peer, so an
		// unspecified one is anomalous whichever way it points.
		{
			name:      "unspecified peer outbound",
			addr:      "0.0.0.0",
			direction: correlation.DirectionOutbound,
			want:      toneDanger,
		},
		{
			name:      "unspecified peer inbound",
			addr:      "::",
			direction: correlation.DirectionInbound,
			want:      toneDanger,
		},

		// The collector stores IPv6 peers unbracketed; the brackets in the table
		// come from net.JoinHostPort at render time. A bracketed value would not
		// parse, so this pins down that the model must never carry one.
		{
			name:      "bracketed ipv6 does not parse",
			addr:      "[2001:db8:4::10]",
			direction: correlation.DirectionOutbound,
			want:      toneMuted,
		},
		{
			name:      "empty",
			addr:      "",
			direction: correlation.DirectionOutbound,
			want:      toneMuted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toneForConnection(models.Connection{RemoteAddr: tc.addr}, tc.direction)

			if got != tc.want {
				t.Errorf("toneForConnection(%q, %v) = %v, want %v",
					tc.addr, tc.direction, got, tc.want)
			}
		})
	}
}

// The same peer must not look more alarming outbound than inbound: direction is
// what separates ordinary traffic from something reaching our listeners.
func TestDirectionOutranksPeerInGrading(t *testing.T) {
	peers := []string{"203.0.113.9", "10.0.0.20", "::1"}

	for _, addr := range peers {
		conn := models.Connection{RemoteAddr: addr}

		inbound := toneForConnection(conn, correlation.DirectionInbound)
		outbound := toneForConnection(conn, correlation.DirectionOutbound)

		if inbound == outbound {
			t.Errorf("%s: inbound and outbound both graded %v", addr, inbound)
		}

		if inbound != toneDanger && inbound != toneWarn {
			t.Errorf("%s: inbound graded %v, want an alerting tone", addr, inbound)
		}

		if outbound == toneDanger || outbound == toneWarn {
			t.Errorf("%s: ordinary outbound traffic graded %v", addr, outbound)
		}
	}
}

// Regression for the reported bug: on a normal workstation almost every
// connection is outbound HTTPS, and colouring those as warnings drowned out the
// one inbound row that mattered.
func TestOutboundTrafficDoesNotDrownOutInbound(t *testing.T) {
	ports := []models.Port{
		{Protocol: "tcp", Addr: "::", Port: "22", State: "LISTEN", PID: -1},
	}

	connections := []models.Connection{
		{Protocol: "tcp", LocalAddr: "10.0.0.10", LocalPort: "34432", RemoteAddr: "198.51.100.25", RemotePort: "443", PID: -1},
		{Protocol: "tcp", LocalAddr: "10.0.0.10", LocalPort: "44692", RemoteAddr: "198.51.100.93", RemotePort: "443", PID: -1},
		{Protocol: "tcp", LocalAddr: "2001:db8:1::1", LocalPort: "51000", RemoteAddr: "2001:db8:4::10", RemotePort: "443", PID: -1},
		// The one that matters: a peer on our SSH listener.
		{Protocol: "tcp", LocalAddr: "::1", LocalPort: "22", RemoteAddr: "::1", RemotePort: "44622", PID: -1},
	}

	rows := connectionRows(connections, ports)

	alerting := 0

	for _, r := range rows {
		// Cell 3 is REMOTE, which carries the connection tone.
		if r[3].tone == toneDanger || r[3].tone == toneWarn {
			alerting++
		}
	}

	if alerting != 1 {
		t.Errorf("%d of %d rows are alerting, want exactly the inbound one",
			alerting, len(rows))
	}

	if got := rows[3][1].text; got != "in" {
		t.Errorf("direction cell = %q, want %q", got, "in")
	}

	if got := rows[0][1].text; got != "out" {
		t.Errorf("direction cell = %q, want %q", got, "out")
	}
}

// 0.0.0.0 stays graded differently between a listener and a peer: binding every
// interface is normal, being the peer of a live connection is not.
func TestUnspecifiedAddressIsGradedPerSide(t *testing.T) {
	listen := toneForListenAddr(models.Port{Addr: "0.0.0.0"})
	remote := toneForConnection(
		models.Connection{RemoteAddr: "0.0.0.0"},
		correlation.DirectionOutbound,
	)

	if listen != toneWarn {
		t.Errorf("listen 0.0.0.0 = %v, want %v", listen, toneWarn)
	}

	if remote != toneDanger {
		t.Errorf("remote 0.0.0.0 = %v, want %v", remote, toneDanger)
	}

	if listen == remote {
		t.Error("the two sides must not collapse to the same tone")
	}
}

func TestToneForEventType(t *testing.T) {
	tests := []struct {
		name      string
		eventType models.AuthEventType
		want      tone
	}{
		{name: "login success", eventType: models.LoginSuccess, want: toneOK},
		{name: "sudo success", eventType: models.SudoSuccess, want: toneOK},
		{name: "su success", eventType: models.SuSuccess, want: toneOK},
		{name: "login failed", eventType: models.LoginFailed, want: toneDanger},
		{name: "sudo failed", eventType: models.SudoFailed, want: toneDanger},
		{name: "su failed", eventType: models.SuFailed, want: toneDanger},
		{name: "invalid user", eventType: models.InvalidUser, want: toneWarn},
		{name: "unknown", eventType: models.AuthEventType("privilege_escalation"), want: toneDefault},
		{name: "empty", eventType: models.AuthEventType(""), want: toneDefault},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toneForEventType(tc.eventType)

			if got != tc.want {
				t.Errorf("toneForEventType(%q) = %v, want %v", tc.eventType, got, tc.want)
			}
		})
	}
}

// knownAuthEventTypes must list every constant in model.AuthEventType. A new
// event type that nobody classified would otherwise fall through to the default
// branch and render in plain grey, hiding a failure in plain sight.
var knownAuthEventTypes = []models.AuthEventType{
	models.LoginSuccess,
	models.LoginFailed,
	models.InvalidUser,
	models.SudoSuccess,
	models.SudoFailed,
	models.SuSuccess,
	models.SuFailed,
}

func TestEveryKnownEventTypeIsClassified(t *testing.T) {
	for _, eventType := range knownAuthEventTypes {
		if got := toneForEventType(eventType); got == toneDefault {
			t.Errorf(
				"%q falls through to the default branch: add it to toneForEventType",
				eventType,
			)
		}
	}
}

// Every tone must resolve to a colour of its own: two tones sharing one colour
// would silently merge two different meanings on screen.
func TestToneForegroundIsDistinctPerTone(t *testing.T) {
	tones := []tone{toneDefault, toneMuted, toneAccent, toneWarn, toneDanger, toneOK}

	seen := make(map[string]tone, len(tones))

	for _, tn := range tones {
		colour := toneForeground(tn)

		if colour == nil {
			t.Fatalf("tone %v has no colour", tn)
		}

		key := fmt.Sprintf("%v", colour)

		if other, ok := seen[key]; ok {
			t.Errorf("tones %v and %v share colour %v", other, tn, colour)
		}

		seen[key] = tn
	}
}

// tone.String exists so a failing assertion names the tone instead of printing
// an integer. A tone that stringifies as another one would make those failures
// actively misleading.
func TestToneString(t *testing.T) {
	tests := []struct {
		tone tone
		want string
	}{
		{tone: toneDefault, want: "toneDefault"},
		{tone: toneMuted, want: "toneMuted"},
		{tone: toneAccent, want: "toneAccent"},
		{tone: toneWarn, want: "toneWarn"},
		{tone: toneDanger, want: "toneDanger"},
		{tone: toneOK, want: "toneOK"},
		{tone: tone(99), want: "toneDefault"},
	}

	for _, tc := range tests {
		if got := tc.tone.String(); got != tc.want {
			t.Errorf("tone(%d).String() = %q, want %q", tc.tone, got, tc.want)
		}
	}
}
