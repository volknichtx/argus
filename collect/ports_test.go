package collect

import (
	"reflect"
	"testing"

	"github.com/volknichtx/argus/model"
)

func TestParseRow(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{
			name: "multiple rows",
			data: []byte("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"),
			want: []string{
				"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
				"udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*",
			},
		},
		{
			name: "empty output",
			data: []byte(""),
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRow(tc.data)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseRow() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAddr string
		wantPort string
		wantErr  bool
	}{
		{
			name:     "ipv4",
			input:    "0.0.0.0:22",
			wantAddr: "0.0.0.0",
			wantPort: "22",
		},
		{
			name:     "ipv4 with interface suffix from real ss output",
			input:    "10.0.0.10%eno1:68",
			wantAddr: "10.0.0.10%eno1",
			wantPort: "68",
		},
		{
			name:     "ipv4 wildcard with interface suffix",
			input:    "0.0.0.0%virbr0:67",
			wantAddr: "0.0.0.0%virbr0",
			wantPort: "67",
		},
		{
			name:     "ipv6 wildcard",
			input:    "[::]:443",
			wantAddr: "::",
			wantPort: "443",
		},
		{
			name:     "global ipv6 from real ss output",
			input:    "[2001:db8:1::10]:55942",
			wantAddr: "2001:db8:1::10",
			wantPort: "55942",
		},
		{
			name:     "wildcard address",
			input:    "*:53",
			wantAddr: "*",
			wantPort: "53",
		},
		{
			name:     "ipv6 link local with ss zone format",
			input:    "[fe80::1234:5678]%eno1:546",
			wantAddr: "fe80::1234:5678%eno1",
			wantPort: "546",
		},
		{
			name:    "invalid address",
			input:   "not-a-host-port",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAddr, gotPort, err := parseAddress(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatalf(
						"parseAddress(%q) error = nil, want error",
						tc.input,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"parseAddress(%q) unexpected error: %v",
					tc.input,
					err,
				)
			}

			if gotAddr != tc.wantAddr {
				t.Errorf("addr = %q, want %q", gotAddr, tc.wantAddr)
			}

			if gotPort != tc.wantPort {
				t.Errorf("port = %q, want %q", gotPort, tc.wantPort)
			}
		})
	}
}

func TestParseProcessName(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantProcess string
		wantPID     int
	}{
		{
			name:        "sshd process",
			input:       `users:(("sshd",pid=4711,fd=3))`,
			wantProcess: "sshd",
			wantPID:     4711,
		},
		{
			name:        "process name with spaces",
			input:       `users:(("helper",pid=4711,fd=3))`,
			wantProcess: "helper",
			wantPID:     4711,
		},
		{
			name:        "missing process data",
			input:       "",
			wantProcess: "undefined",
			wantPID:     -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotProcess, gotPID, err := parseProcessName(tc.input)
			if err != nil {
				t.Fatalf(
					"parseProcessName(%q) unexpected error: %v",
					tc.input,
					err,
				)
			}

			if gotProcess != tc.wantProcess {
				t.Errorf(
					"process = %q, want %q",
					gotProcess,
					tc.wantProcess,
				)
			}

			if gotPID != tc.wantPID {
				t.Errorf("pid = %d, want %d", gotPID, tc.wantPID)
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name string
		rows []string
		want []model.Port
	}{
		{
			name: "tcp listener with process",
			rows: []string{
				`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=4711,fd=3))`,
			},
			want: []model.Port{
				{
					Protocol: "tcp",
					Addr:     "0.0.0.0",
					Port:     "22",
					PID:      4711,
					Process:  "sshd",
					State:    "LISTEN",
				},
			},
		},
		{
			name: "udp listener without process",
			rows: []string{
				"udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*",
			},
			want: []model.Port{
				{
					Protocol: "udp",
					Addr:     "0.0.0.0",
					Port:     "5353",
					PID:      -1,
					Process:  "undefined",
					State:    "UNCONN",
				},
			},
		},
		{
			name: "short malformed row is ignored",
			rows: []string{"tcp LISTEN"},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePorts(tc.rows)

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf(
					"parsePorts() = %#v, want %#v",
					got,
					tc.want,
				)
			}
		})
	}
}
