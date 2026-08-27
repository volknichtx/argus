package collect

import (
	"os"
	"strings"
	"testing"
)

func TestParsePortsFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/ss_arch.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	rows := parseRow(data)
	if len(rows) == 0 {
		t.Fatal("fixture contains no rows")
	}

	// ss_arch.txt was captured without -H and therefore contains one header
	// row. PortCollector uses `ss -H -lntup`, so production output does not.
	// Keep parsePorts focused on production rows and remove only the verified
	// fixture header here.
	if !strings.HasPrefix(rows[0], "Netid ") {
		t.Fatalf("unexpected fixture header: %q", rows[0])
	}
	rows = rows[1:]

	ports := parsePorts(rows)

	// Freeze the number of real socket rows in this captured fixture so a
	// future parser change cannot silently drop rows.
	if len(ports) != 15 {
		t.Fatalf("ports = %d, want 15", len(ports))
	}

	tests := []struct {
		name     string
		protocol string
		addr     string
		port     string
		state    string
		process  string
		pid      int
	}{
		{
			name:     "process-less listener",
			protocol: "udp",
			addr:     "10.1.0.1",
			port:     "53",
			state:    "UNCONN",
			process:  "undefined",
			pid:      -1,
		},
		{
			name:     "process name containing space",
			protocol: "udp",
			addr:     "10.0.0.10",
			port:     "50312",
			state:    "UNCONN",
			process:  "helper",
			pid:      3343,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, port := range ports {
				if port.Protocol != tc.protocol ||
					port.Addr != tc.addr ||
					port.Port != tc.port {
					continue
				}

				if port.State != tc.state {
					t.Errorf("State = %q, want %q", port.State, tc.state)
				}

				if port.Process != tc.process {
					t.Errorf("Process = %q, want %q", port.Process, tc.process)
				}

				if port.PID != tc.pid {
					t.Errorf("PID = %d, want %d", port.PID, tc.pid)
				}

				return
			}

			t.Fatalf(
				"port not found: %s %s:%s",
				tc.protocol,
				tc.addr,
				tc.port,
			)
		})
	}
}
