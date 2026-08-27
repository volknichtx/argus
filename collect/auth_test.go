package collect

import (
	"testing"

	"github.com/volknichtx/argus/model"
)

func TestParseSSHAuthMessage(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		wantType    model.AuthEventType
		wantUser    string
		wantIP      string
		wantPort    int
		wantSuccess bool
		wantMatched bool
	}{
		{
			name:        "failed password for root",
			message:     "Failed password for root from 127.0.0.1 port 44352 ssh2",
			wantType:    model.LoginFailed,
			wantUser:    "root",
			wantIP:      "127.0.0.1",
			wantPort:    44352,
			wantSuccess: false,
			wantMatched: true,
		},
		{
			name:        "accepted password over ipv6",
			message:     "Accepted password for alice from ::1 port 49910 ssh2",
			wantType:    model.LoginSuccess,
			wantUser:    "alice",
			wantIP:      "::1",
			wantPort:    49910,
			wantSuccess: true,
			wantMatched: true,
		},
		{
			name:        "failed password for invalid user",
			message:     "Failed password for invalid user attacker from 10.0.0.50 port 55123 ssh2",
			wantType:    model.InvalidUser,
			wantUser:    "attacker",
			wantIP:      "10.0.0.50",
			wantPort:    55123,
			wantSuccess: false,
			wantMatched: true,
		},
		{
			name:        "irrelevant sshd message",
			message:     "Server listening on 0.0.0.0 port 22.",
			wantMatched: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := model.AuthEventLog{}

			gotMatched := parseSSHAuthMessage(&event, tc.message)

			if gotMatched != tc.wantMatched {
				t.Fatalf("matched = %v, want %v", gotMatched, tc.wantMatched)
			}

			if !tc.wantMatched {
				return
			}

			if event.EventType != tc.wantType {
				t.Errorf("EventType = %q, want %q", event.EventType, tc.wantType)
			}

			if event.User != tc.wantUser {
				t.Errorf("User = %q, want %q", event.User, tc.wantUser)
			}

			if gotIP := event.SourceIP.String(); gotIP != tc.wantIP {
				t.Errorf("SourceIP = %q, want %q", gotIP, tc.wantIP)
			}

			if event.SourcePort != tc.wantPort {
				t.Errorf("SourcePort = %d, want %d", event.SourcePort, tc.wantPort)
			}

			if event.Success != tc.wantSuccess {
				t.Errorf("Success = %v, want %v", event.Success, tc.wantSuccess)
			}
		})
	}
}
