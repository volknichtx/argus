package collect

import (
	"reflect"
	"testing"

	"github.com/volknichtx/argus/model"
)

func TestParseSessions(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []model.UserSession
	}{
		{
			name:   "local tty session",
			output: "alice tty2 2026-08-15 18:32 old 1143\n",
			want: []model.UserSession{
				{
					User:      "alice",
					TTY:       "tty2",
					LoginDate: "2026-08-15",
					LoginTime: "18:32",
					Idle:      "old",
					PID:       1143,
					Source:    "local",
				},
			},
		},
		{
			name:   "remote ipv6 session",
			output: "alice pts/1 2026-08-15 19:05 . 5832 (::1)\n",
			want: []model.UserSession{
				{
					User:      "alice",
					TTY:       "pts/1",
					LoginDate: "2026-08-15",
					LoginTime: "19:05",
					Idle:      ".",
					PID:       5832,
					Source:    "::1",
				},
			},
		},
		{
			name: "multiple sessions",
			output: "alice tty2 2026-08-15 18:32 old 1143\n" +
				"root pts/3 2026-08-15 20:01 00:02 9123 (10.0.0.30)\n",
			want: []model.UserSession{
				{
					User:      "alice",
					TTY:       "tty2",
					LoginDate: "2026-08-15",
					LoginTime: "18:32",
					Idle:      "old",
					PID:       1143,
					Source:    "local",
				},
				{
					User:      "root",
					TTY:       "pts/3",
					LoginDate: "2026-08-15",
					LoginTime: "20:01",
					Idle:      "00:02",
					PID:       9123,
					Source:    "10.0.0.30",
				},
			},
		},
		{
			name:   "malformed and empty lines are ignored",
			output: "\ninvalid line\n\n",
			want:   nil,
		},
		{
			name:   "invalid pid keeps minus one",
			output: "alice pts/4 2026-08-15 20:20 . not-a-pid (host.example)\n",
			want: []model.UserSession{
				{
					User:      "alice",
					TTY:       "pts/4",
					LoginDate: "2026-08-15",
					LoginTime: "20:20",
					Idle:      ".",
					PID:       -1,
					Source:    "host.example",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []model.UserSession

			parseSessions(tc.output, &got)

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseSessions() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
