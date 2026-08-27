package collect

import (
	"io"
	"strings"
	"testing"
)

// PortCollector must ask ss for listening sockets in the numeric, headerless
// form the parser expects, and hand back what it parsed.
func TestPortCollectorRunsSsAndParses(t *testing.T) {
	run := fakeCommand(t, `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=4711,fd=3))`+"\n", 0)

	ports, err := PortCollector()
	if err != nil {
		t.Fatalf("PortCollector(): %v", err)
	}

	if got := run.name(); got != "ss" {
		t.Errorf("ran %q, want ss", got)
	}

	// -H keeps the header out, and -n keeps ss from resolving service names
	// into words the address parser cannot split.
	for _, want := range []string{"-H", "-lntup"} {
		if !run.arg(want) {
			t.Errorf("ss was called without %q: %v", want, run.args())
		}
	}

	if len(ports) != 1 {
		t.Fatalf("ports = %d, want 1", len(ports))
	}

	if ports[0].Port != "22" || ports[0].Process != "sshd" {
		t.Errorf("port = %+v, want the parsed sshd listener", ports[0])
	}
}

func TestConnectionCollectorRunsSsAndParses(t *testing.T) {
	run := fakeCommand(t, "tcp ESTAB 0 0 192.0.2.10:22 192.0.2.20:63112\n", 0)

	connections, err := ConnectionCollector()
	if err != nil {
		t.Fatalf("ConnectionCollector(): %v", err)
	}

	if got := run.name(); got != "ss" {
		t.Errorf("ran %q, want ss", got)
	}

	if !run.arg("-tunp") {
		t.Errorf("ss was called without -tunp: %v", run.args())
	}

	if len(connections) != 1 {
		t.Fatalf("connections = %d, want 1", len(connections))
	}

	if connections[0].RemoteAddr != "192.0.2.20" {
		t.Errorf("remote = %q, want 192.0.2.20", connections[0].RemoteAddr)
	}
}

func TestSessionCollectorRunsWhoAndParses(t *testing.T) {
	run := fakeCommand(t, "alice pts/1 2026-08-15 19:05 . 5832 (192.0.2.20)\n", 0)

	sessions, err := SessionCollector()
	if err != nil {
		t.Fatalf("SessionCollector(): %v", err)
	}

	if got := run.name(); got != "who" {
		t.Errorf("ran %q, want who", got)
	}

	// -u is what adds the PID and the origin column the correlation joins on.
	if !run.arg("-u") {
		t.Errorf("who was called without -u: %v", run.args())
	}

	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}

	if sessions[0].Source != "192.0.2.20" {
		t.Errorf("source = %q, want 192.0.2.20", sessions[0].Source)
	}
}

// A tool that fails must surface as an error rather than as an empty pane, so
// the status bar can say the collector is broken instead of implying the
// machine has no sockets.
func TestCollectorsReportToolFailure(t *testing.T) {
	tests := []struct {
		name    string
		collect func() error
	}{
		{
			name: "ss for ports",
			collect: func() error {
				_, err := PortCollector()
				return err
			},
		},
		{
			name: "ss for connections",
			collect: func() error {
				_, err := ConnectionCollector()
				return err
			},
		},
		{
			name: "who",
			collect: func() error {
				_, err := SessionCollector()
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeCommand(t, "", 1)

			if err := tc.collect(); err == nil {
				t.Fatal("a failing tool produced no error")
			}
		})
	}
}

// Empty output is a legitimate answer — a machine really can have no sessions —
// and must not be confused with a failure.
func TestCollectorsAcceptEmptyOutput(t *testing.T) {
	fakeCommand(t, "", 0)

	ports, err := PortCollector()
	if err != nil {
		t.Fatalf("PortCollector(): %v", err)
	}

	if len(ports) != 0 {
		t.Errorf("ports = %d, want none", len(ports))
	}
}

// One unreadable row must cost that row and nothing else. Failing the batch
// used to blank the whole pane over a single line.
func TestUnparseableRowsAreSkippedNotFatal(t *testing.T) {
	t.Run("listening sockets", func(t *testing.T) {
		ports := parsePorts([]string{
			"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
			"tcp LISTEN 0 128 this-is-not-an-address 0.0.0.0:*",
			"udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*",
		})

		if len(ports) != 2 {
			t.Fatalf("ports = %d, want the two readable rows", len(ports))
		}

		if ports[0].Port != "22" || ports[1].Port != "5353" {
			t.Errorf("ports = %+v, want 22 and 5353", ports)
		}
	})

	t.Run("connections", func(t *testing.T) {
		connections := parseConnections([]string{
			"tcp ESTAB 0 0 192.0.2.10:22 192.0.2.20:63112",
			"tcp ESTAB 0 0 192.0.2.10:22 this-is-not-an-address",
			"tcp ESTAB 0 0 this-is-not-an-address 192.0.2.20:63112",
			"tcp ESTAB 0 0 192.0.2.10:443 192.0.2.30:51000",
		})

		if len(connections) != 2 {
			t.Fatalf("connections = %d, want the two readable rows", len(connections))
		}

		if connections[0].LocalPort != "22" || connections[1].LocalPort != "443" {
			t.Errorf("connections = %+v, want 22 and 443", connections)
		}
	})

	t.Run("process data keeps the socket", func(t *testing.T) {
		// A PID too large for an int makes the process data unreadable, but the
		// socket itself is real and must survive with an unknown owner.
		ports := parsePorts([]string{
			`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=99999999999999999999,fd=3))`,
		})

		if len(ports) != 1 {
			t.Fatalf("ports = %d, want the socket to survive", len(ports))
		}

		if ports[0].PID != -1 || ports[0].Process != "undefined" {
			t.Errorf("port = %+v, want an unknown process", ports[0])
		}
	})
}

// The skipped rows are not silently lost: they reach the diagnostics log when
// one is configured.
func TestSkippedRowsAreLogged(t *testing.T) {
	var buffer strings.Builder

	debugLog.SetOutput(&buffer)
	t.Cleanup(func() { debugLog.SetOutput(io.Discard) })

	parsePorts([]string{"tcp LISTEN 0 128 this-is-not-an-address 0.0.0.0:*"})

	if !strings.Contains(buffer.String(), "this-is-not-an-address") {
		t.Errorf("log = %q, want the skipped row named", buffer.String())
	}
}
