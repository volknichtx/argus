package collect

import (
	"testing"

	"github.com/volknichtx/argus/model"
)

// parseAuthMessage routes by the service authEventFilter resolved. A service
// with no parser must be refused rather than produce a blank event.
func TestParseAuthMessageDispatchesByService(t *testing.T) {
	tests := []struct {
		name        string
		service     string
		message     string
		wantMatched bool
		wantType    model.AuthEventType
	}{
		{
			name:        "sshd",
			service:     "sshd",
			message:     "Accepted publickey for alice from 192.0.2.20 port 49910 ssh2",
			wantMatched: true,
			wantType:    model.LoginSuccess,
		},
		{
			name:        "sudo",
			service:     "sudo",
			message:     "alice : TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
			wantMatched: true,
			wantType:    model.SudoSuccess,
		},
		{
			name:        "su",
			service:     "su",
			message:     "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)",
			wantMatched: true,
			wantType:    model.SuSuccess,
		},
		{
			name:        "login",
			service:     "login",
			message:     "pam_unix(login:session): session opened for user alice(uid=1000)",
			wantMatched: true,
			wantType:    model.LoginSuccess,
		},
		{
			name:    "service without a parser",
			service: "cron",
			message: "anything at all",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := model.AuthEventLog{Service: tc.service, Message: tc.message}

			if got := parseAuthMessage(&event); got != tc.wantMatched {
				t.Fatalf("parseAuthMessage() = %v, want %v", got, tc.wantMatched)
			}

			if !tc.wantMatched {
				return
			}

			if event.EventType != tc.wantType {
				t.Errorf("EventType = %q, want %q", event.EventType, tc.wantType)
			}
		})
	}
}

func TestParseSudoAuthMessage(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		wantMatched bool
		wantType    model.AuthEventType
		wantUser    string
		wantSuccess bool
		wantSource  string
	}{
		{
			name:        "successful command",
			message:     "alice : TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/pacman -Syu",
			wantMatched: true,
			wantType:    model.SudoSuccess,
			wantUser:    "alice",
			wantSuccess: true,
		},
		{
			name:        "pam authentication failure",
			message:     "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/2 ruser=alice rhost=  user=alice",
			wantMatched: true,
			wantType:    model.SudoFailed,
			wantUser:    "alice",
		},
		{
			name:        "incorrect password attempt",
			message:     "alice : 1 incorrect password attempt ; TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
			wantMatched: true,
			wantType:    model.SudoFailed,
			wantUser:    "alice",
		},
		{
			// sudo over ssh carries the origin, which is what makes the event
			// correlatable to a remote host at all.
			name:        "failure carrying a remote host",
			message:     "pam_unix(sudo:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/3 ruser=bob rhost=192.0.2.20 user=bob",
			wantMatched: true,
			wantType:    model.SudoFailed,
			wantUser:    "bob",
			wantSource:  "192.0.2.20",
		},
		{
			name:    "unrelated sudo chatter",
			message: "unable to resolve host workstation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := model.AuthEventLog{}

			if got := parseSudoAuthMessage(&event, tc.message); got != tc.wantMatched {
				t.Fatalf("parseSudoAuthMessage() = %v, want %v", got, tc.wantMatched)
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

			if event.Success != tc.wantSuccess {
				t.Errorf("Success = %v, want %v", event.Success, tc.wantSuccess)
			}

			source := ""
			if event.SourceIP != nil {
				source = event.SourceIP.String()
			}

			if source != tc.wantSource {
				t.Errorf("SourceIP = %q, want %q", source, tc.wantSource)
			}
		})
	}
}

func TestParseSuAuthMessage(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		wantMatched bool
		wantType    model.AuthEventType
		wantUser    string
		wantSuccess bool
	}{
		{
			name:        "session opened names the target account",
			message:     "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)",
			wantMatched: true,
			wantType:    model.SuSuccess,
			wantUser:    "root",
			wantSuccess: true,
		},
		{
			name:        "authentication failure",
			message:     "pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/2 ruser=alice rhost=  user=root",
			wantMatched: true,
			wantType:    model.SuFailed,
			wantUser:    "root",
		},
		{
			name:    "unrelated su chatter",
			message: "FAILED SU (to root) alice on pts/2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := model.AuthEventLog{}

			if got := parseSuAuthMessage(&event, tc.message); got != tc.wantMatched {
				t.Fatalf("parseSuAuthMessage() = %v, want %v", got, tc.wantMatched)
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

			if event.Success != tc.wantSuccess {
				t.Errorf("Success = %v, want %v", event.Success, tc.wantSuccess)
			}
		})
	}
}

func TestParseLoginAuthMessage(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		wantMatched bool
		wantType    model.AuthEventType
		wantUser    string
		wantSuccess bool
		wantSource  string
	}{
		{
			name:        "session opened",
			message:     "pam_unix(login:session): session opened for user alice(uid=1000) by LOGIN(uid=0)",
			wantMatched: true,
			wantType:    model.LoginSuccess,
			wantUser:    "alice",
			wantSuccess: true,
		},
		{
			name:        "login on a tty",
			message:     "LOGIN ON tty2 BY alice",
			wantMatched: true,
			wantType:    model.LoginSuccess,
			wantSuccess: true,
		},
		{
			name:        "pam authentication failure",
			message:     "pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 tty=tty2 ruser= rhost=  user=alice",
			wantMatched: true,
			wantType:    model.LoginFailed,
			wantUser:    "alice",
		},
		{
			name:        "failed login carrying a remote host",
			message:     "FAILED LOGIN 1 FROM 192.0.2.30 FOR alice, Authentication failure rhost=192.0.2.30 user=alice",
			wantMatched: true,
			wantType:    model.LoginFailed,
			wantUser:    "alice",
			wantSource:  "192.0.2.30",
		},
		{
			name:    "unrelated login chatter",
			message: "pam_unix(login:session): session closed for user alice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := model.AuthEventLog{}

			if got := parseLoginAuthMessage(&event, tc.message); got != tc.wantMatched {
				t.Fatalf("parseLoginAuthMessage() = %v, want %v", got, tc.wantMatched)
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

			if event.Success != tc.wantSuccess {
				t.Errorf("Success = %v, want %v", event.Success, tc.wantSuccess)
			}

			source := ""
			if event.SourceIP != nil {
				source = event.SourceIP.String()
			}

			if source != tc.wantSource {
				t.Errorf("SourceIP = %q, want %q", source, tc.wantSource)
			}
		})
	}
}

// An sshd line whose wording the metadata patterns do not cover still counts as
// an authentication event; it just carries no user or origin. Dropping it would
// hide a failure, inventing a user would fabricate one.
func TestSSHMetadataIsOptional(t *testing.T) {
	event := model.AuthEventLog{}

	if !parseSSHAuthMessage(&event, "Failed none for root") {
		t.Fatal("an sshd failure without metadata was dropped")
	}

	if event.EventType != model.LoginFailed {
		t.Errorf("EventType = %q, want %q", event.EventType, model.LoginFailed)
	}

	if event.SourceIP != nil {
		t.Errorf("SourceIP = %v, want none to be invented", event.SourceIP)
	}

	if event.User != "" {
		t.Errorf("User = %q, want none to be invented", event.User)
	}
}

// sshd wraps IPv6 origins in brackets, and the address has to survive parsing
// or the event cannot be joined to its host.
func TestSSHIPv6SourceIsParsed(t *testing.T) {
	event := model.AuthEventLog{}

	if !parseSSHAuthMessage(&event, "Accepted password for alice from 2001:db8::20 port 49910 ssh2") {
		t.Fatal("an IPv6 login was not recognised")
	}

	if got := event.SourceIP.String(); got != "2001:db8::20" {
		t.Errorf("SourceIP = %q, want 2001:db8::20", got)
	}

	if event.SourcePort != 49910 {
		t.Errorf("SourcePort = %d, want 49910", event.SourcePort)
	}
}
