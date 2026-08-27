package collect

import (
	"testing"

	"github.com/volknichtx/argus/model"
)

// The audit session is the only handle a privilege change carries, so it has to
// survive the journal round trip or the correlation has nothing to join on.
func TestAuditSessionReachesTheEvent(t *testing.T) {
	line := `{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1756240000000000",` +
		`"SYSLOG_IDENTIFIER":"su","_AUDIT_SESSION":"5",` +
		`"MESSAGE":"pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)"}`

	fakeCommand(t, line+"\n", 0)

	events, _, err := CollectAuthEvents("")
	if err != nil {
		t.Fatalf("CollectAuthEvents(): %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}

	event := events[0]

	if event.AuditSession != "5" {
		t.Errorf("AuditSession = %q, want 5", event.AuditSession)
	}

	if event.TargetUser != "root" {
		t.Errorf("TargetUser = %q, want root", event.TargetUser)
	}

	if !event.IsEscalation() {
		t.Error("a successful su to root is not reported as an escalation")
	}
}

// An entry without the field must not invent one.
func TestMissingAuditSessionStaysEmpty(t *testing.T) {
	line := `{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1756240000000000",` +
		`"SYSLOG_IDENTIFIER":"sshd",` +
		`"MESSAGE":"Accepted password for alice from 192.0.2.20 port 49910 ssh2"}`

	fakeCommand(t, line+"\n", 0)

	events, _, err := CollectAuthEvents("")
	if err != nil {
		t.Fatalf("CollectAuthEvents(): %v", err)
	}

	if events[0].AuditSession != "" {
		t.Errorf("AuditSession = %q, want empty", events[0].AuditSession)
	}
}

// Which account a privilege change switched to is what separates an escalation
// from an ordinary user switch, and the two services word it differently.
func TestTargetUserIsParsedFromBothServices(t *testing.T) {
	tests := []struct {
		name       string
		service    string
		message    string
		wantTarget string
		wantActor  string
		wantEscal  bool
	}{
		{
			name:       "sudo command line names the account it ran as",
			service:    "sudo",
			message:    "alice : TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
			wantTarget: "root",
			wantActor:  "alice",
			wantEscal:  true,
		},
		{
			name:       "su pam session line",
			service:    "su",
			message:    "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)",
			wantTarget: "root",
			wantActor:  "root",
			wantEscal:  true,
		},
		{
			name:       "sudo running as an ordinary account",
			service:    "sudo",
			message:    "alice : TTY=pts/2 ; PWD=/home/alice ; USER=backup ; COMMAND=/usr/bin/rsync",
			wantTarget: "backup",
			wantActor:  "alice",
			wantEscal:  false,
		},
		{
			name:       "su to an ordinary account",
			service:    "su",
			message:    "pam_unix(su:session): session opened for user backup(uid=1002) by alice(uid=1000)",
			wantTarget: "backup",
			wantActor:  "backup",
			wantEscal:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := model.AuthEventLog{Service: tc.service, Message: tc.message}

			if !parseAuthMessage(&event) {
				t.Fatal("message was not recognised")
			}

			if event.TargetUser != tc.wantTarget {
				t.Errorf("TargetUser = %q, want %q", event.TargetUser, tc.wantTarget)
			}

			if event.User != tc.wantActor {
				t.Errorf("User = %q, want %q", event.User, tc.wantActor)
			}

			if got := event.IsEscalation(); got != tc.wantEscal {
				t.Errorf("IsEscalation() = %v, want %v", got, tc.wantEscal)
			}
		})
	}
}

// sudo writes two lines for one invocation: its own TTY=/USER=/COMMAND= line and
// a pam session line. Only the first is an event; recognising both would report
// one sudo as two escalations and double the ROOT count for the host.
func TestSudoPamSessionLineIsNotASecondEvent(t *testing.T) {
	event := model.AuthEventLog{
		Service: "sudo",
		Message: "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
	}

	if parseAuthMessage(&event) {
		t.Error("the sudo pam session line is reported as an event of its own")
	}
}

// A failed privilege change is never an escalation, whatever it aimed at.
func TestFailedPrivilegeChangeIsNotAnEscalation(t *testing.T) {
	event := model.AuthEventLog{
		Service: "su",
		Message: "pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/2 ruser=alice rhost=  user=root",
	}

	if !parseAuthMessage(&event) {
		t.Fatal("message was not recognised")
	}

	if event.TargetUser != "root" {
		t.Errorf("TargetUser = %q, want root", event.TargetUser)
	}

	if event.IsEscalation() {
		t.Error("a failed su is reported as an escalation")
	}

	if !event.IsPrivilegeChange() {
		t.Error("a failed su is not reported as a privilege change")
	}
}
