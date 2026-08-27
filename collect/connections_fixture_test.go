package collect

import (
	"os"
	"testing"
)

func TestParseConnectionsFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/ss_connections_fixture.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	rows := parseRow(data)

	got := parseConnections(rows)

	// This fixture is intentionally frozen at 26 real ESTAB sockets.
	// If rows are silently lost in the future, this test should fail.
	if len(got) != 26 {
		t.Fatalf("connections = %d, want 26", len(got))
	}

	tests := []struct {
		name       string
		protocol   string
		localAddr  string
		localPort  string
		remoteAddr string
		remotePort string
		process    string
		pid        int
	}{
		{
			name:       "udp dhcp without process metadata",
			protocol:   "udp",
			localAddr:  "10.0.0.10%eno1",
			localPort:  "68",
			remoteAddr: "10.0.0.1",
			remotePort: "67",
			process:    "undefined",
			pid:        -1,
		},
		{
			name:       "nonzero recv queue keeps column positions",
			protocol:   "tcp",
			localAddr:  "127.0.0.1",
			localPort:  "42968",
			remoteAddr: "127.0.0.1",
			remotePort: "57343",
			process:    "gamehelper",
			pid:        2355,
		},
		{
			name:       "global ipv6 mediaplayer connection",
			protocol:   "tcp",
			localAddr:  "2001:db8:1::10",
			localPort:  "55942",
			remoteAddr: "2001:db8:2:7c5::",
			remotePort: "443",
			process:    "mediaplayer",
			pid:        156586,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, connection := range got {
				if connection.Protocol != tc.protocol ||
					connection.LocalAddr != tc.localAddr ||
					connection.LocalPort != tc.localPort ||
					connection.RemoteAddr != tc.remoteAddr ||
					connection.RemotePort != tc.remotePort {
					continue
				}

				if connection.State != establishedState {
					t.Errorf(
						"State = %q, want %q",
						connection.State,
						establishedState,
					)
				}

				if connection.Process != tc.process {
					t.Errorf(
						"Process = %q, want %q",
						connection.Process,
						tc.process,
					)
				}

				if connection.PID != tc.pid {
					t.Errorf(
						"PID = %d, want %d",
						connection.PID,
						tc.pid,
					)
				}

				return
			}

			t.Fatalf(
				"connection not found: %s %s:%s -> %s:%s",
				tc.protocol,
				tc.localAddr,
				tc.localPort,
				tc.remoteAddr,
				tc.remotePort,
			)
		})
	}
}
