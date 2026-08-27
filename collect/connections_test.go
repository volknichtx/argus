package collect

import (
	"reflect"
	"testing"

	"github.com/volknichtx/argus/model"
)

func TestParseConnections(t *testing.T) {
	tests := []struct {
		name string
		rows []string
		want []model.Connection
	}{
		{
			name: "established ssh connection",
			rows: []string{
				`tcp ESTAB 0 0 10.0.0.10:22 10.0.0.20:63112 users:(("sshd",pid=4711,fd=4))`,
			},
			want: []model.Connection{
				{
					Protocol:   "tcp",
					LocalAddr:  "10.0.0.10",
					LocalPort:  "22",
					RemoteAddr: "10.0.0.20",
					RemotePort: "63112",
					PID:        4711,
					Process:    "sshd",
					State:      "ESTAB",
				},
			},
		},
		{
			name: "connection without process metadata",
			rows: []string{
				"tcp ESTAB 0 0 10.0.0.2:443 10.0.0.8:52000",
			},
			want: []model.Connection{
				{
					Protocol:   "tcp",
					LocalAddr:  "10.0.0.2",
					LocalPort:  "443",
					RemoteAddr: "10.0.0.8",
					RemotePort: "52000",
					PID:        -1,
					Process:    "undefined",
					State:      "ESTAB",
				},
			},
		},
		{
			name: "real style udp connection with interface suffix",
			rows: []string{
				"udp ESTAB 0 0 10.0.0.10%eno1:68 10.0.0.1:67",
			},
			want: []model.Connection{
				{
					Protocol:   "udp",
					LocalAddr:  "10.0.0.10%eno1",
					LocalPort:  "68",
					RemoteAddr: "10.0.0.1",
					RemotePort: "67",
					PID:        -1,
					Process:    "undefined",
					State:      "ESTAB",
				},
			},
		},
		{
			name: "real style global ipv6 connection",
			rows: []string{
				`tcp ESTAB 0 0 [2001:db8:1::10]:55942 [2001:db8:2:7c5::]:443 users:(("mediaplayer",pid=156586,fd=25))`,
			},
			want: []model.Connection{
				{
					Protocol:   "tcp",
					LocalAddr:  "2001:db8:1::10",
					LocalPort:  "55942",
					RemoteAddr: "2001:db8:2:7c5::",
					RemotePort: "443",
					PID:        156586,
					Process:    "mediaplayer",
					State:      "ESTAB",
				},
			},
		},
		{
			name: "unconnected udp socket is ignored",
			rows: []string{
				"udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*",
			},
			want: nil,
		},
		{
			name: "malformed row is ignored",
			rows: []string{
				"tcp ESTAB",
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseConnections(tc.rows)

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf(
					"parseConnections() = %#v, want %#v",
					got,
					tc.want,
				)
			}
		})
	}
}
