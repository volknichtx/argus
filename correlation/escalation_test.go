package correlation

import (
	"testing"
	"time"

	"github.com/volknichtx/argus/model"
)

// escalation builds a su-to-root event as journald reports it: no source
// address of its own, only the login session it ran in.
func escalation(auditSession string) model.AuthEventLog {
	return model.AuthEventLog{
		Timestamp:    time.Date(2026, 8, 27, 9, 53, 49, 0, time.UTC),
		Service:      "su",
		EventType:    model.SuSuccess,
		User:         "root",
		TargetUser:   "root",
		AuditSession: auditSession,
		Success:      true,
	}
}

// remoteSession is a login who reported with an origin and logind gave an id.
func remoteSession(id, tty, source string) model.UserSession {
	return model.UserSession{User: "alice", TTY: tty, PID: 5832, Source: source, ID: id}
}

// The headline of the whole join: someone logs in over ssh and becomes root.
// su carries no address, so without following its login session back to where
// that session came from, the escalation is an anonymous local event.
func TestEscalationIsAttributedToTheHostThatLoggedIn(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{conn("10.0.0.10", "22", "203.0.113.9", "51000")},
		[]model.UserSession{remoteSession("5", "pts/3", "203.0.113.9")},
		[]model.AuthEventLog{
			authEvent("203.0.113.9", 51000, "alice", model.LoginSuccess, true),
			escalation("5"),
		},
	)

	host := findHost(t, hosts, "203.0.113.9")

	if got := host.EscalationCount(); got != 1 {
		t.Errorf("escalations = %d, want 1", got)
	}

	// The login and the escalation are different things and must not be
	// conflated: one ssh login that ran su twice is one login, not three.
	if got := host.LoginCount(); got != 1 {
		t.Errorf("logins = %d, want 1", got)
	}

	if got := host.Concern; got != ConcernCritical {
		t.Errorf("concern = %v, want %v", got, ConcernCritical)
	}

	users := host.Users()
	if len(users) != 2 || users[0] != "alice" || users[1] != "root" {
		t.Errorf("users = %v, want [alice root]", users)
	}
}

// An escalation stands on its own: the login that opened the session may
// already have aged out of the retained auth window.
func TestEscalationAloneIsCritical(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		nil,
		[]model.UserSession{remoteSession("5", "pts/3", "203.0.113.9")},
		[]model.AuthEventLog{escalation("5")},
	)

	host := findHost(t, hosts, "203.0.113.9")

	if got := host.Concern; got != ConcernCritical {
		t.Errorf("concern = %v, want %v", got, ConcernCritical)
	}
}

// Where the link cannot be made exactly it is dropped. A missed escalation is
// recoverable; attributing root to the wrong login is not.
func TestUnlinkableEscalationsAreDropped(t *testing.T) {
	tests := []struct {
		name      string
		sessions  []model.UserSession
		event     model.AuthEventLog
		rationale string
	}{
		{
			name:      "session logind never identified",
			sessions:  []model.UserSession{{User: "alice", TTY: "pts/3", Source: "203.0.113.9"}},
			event:     escalation("5"),
			rationale: "no id to join on",
		},
		{
			name:      "session has already ended",
			sessions:  []model.UserSession{remoteSession("5", "pts/3", "203.0.113.9")},
			event:     escalation("17"),
			rationale: "the id names a session who no longer reports",
		},
		{
			name:      "escalation carries no session at all",
			sessions:  []model.UserSession{remoteSession("5", "pts/3", "203.0.113.9")},
			event:     escalation(""),
			rationale: "nothing to follow",
		},
		{
			name:      "the session is local",
			sessions:  []model.UserSession{remoteSession("5", "tty1", "local")},
			event:     escalation("5"),
			rationale: "a console login has no remote host to blame",
		},
		{
			name:      "the session origin is a hostname",
			sessions:  []model.UserSession{remoteSession("5", "pts/3", "workstation.lan")},
			event:     escalation("5"),
			rationale: "would need DNS to resolve back to an address",
		},
		{
			name:      "the session came from loopback",
			sessions:  []model.UserSession{remoteSession("5", "pts/3", "::1")},
			event:     escalation("5"),
			rationale: "this machine talking to itself is not an attack surface",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hosts := Correlate(testPorts(), nil, tc.sessions, []model.AuthEventLog{tc.event})

			for _, host := range hosts {
				if host.EscalationCount() != 0 {
					t.Errorf("escalation attributed to %s, want none: %s",
						host.Address, tc.rationale)
				}
			}
		})
	}
}

// Loopback keeps its exemption even with an escalation on it: an adversary who
// already holds local access is past everything this tool watches.
func TestLoopbackEscalationIsStillNormal(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		[]model.Connection{conn("::1", "22", "::1", "44622")},
		[]model.UserSession{remoteSession("5", "pts/3", "::1")},
		[]model.AuthEventLog{
			authEvent("::1", 44622, "alice", model.LoginSuccess, true),
			escalation("5"),
		},
	)

	host := findHost(t, hosts, "::1")

	if host.Concern != ConcernNormal {
		t.Errorf("concern = %v, want %v", host.Concern, ConcernNormal)
	}
}

// Two sessions claiming one identifier make the link ambiguous, and an
// ambiguous link would blame one of them at random.
func TestAmbiguousSessionIdentifierDropsTheLink(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		nil,
		[]model.UserSession{
			remoteSession("5", "pts/3", "203.0.113.9"),
			remoteSession("5", "pts/4", "198.51.100.7"),
		},
		[]model.AuthEventLog{escalation("5")},
	)

	for _, host := range hosts {
		if host.EscalationCount() != 0 {
			t.Errorf("escalation attributed to %s despite two sessions sharing the id",
				host.Address)
		}
	}
}

// The same session reported twice is not ambiguous, only repeated.
func TestRepeatedSessionKeepsTheLink(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		nil,
		[]model.UserSession{
			remoteSession("5", "pts/3", "203.0.113.9"),
			remoteSession("5", "pts/3", "203.0.113.9"),
		},
		[]model.AuthEventLog{escalation("5")},
	)

	host := findHost(t, hosts, "203.0.113.9")

	if got := host.EscalationCount(); got != 1 {
		t.Errorf("escalations = %d, want 1", got)
	}
}

// A switch to an ordinary account is a user switch, not an escalation. Only the
// crossing into root is the event this tool is about.
func TestSwitchToOrdinaryAccountIsNotAnEscalation(t *testing.T) {
	event := escalation("5")
	event.User = "backup"
	event.TargetUser = "backup"

	hosts := Correlate(
		testPorts(),
		nil,
		[]model.UserSession{remoteSession("5", "pts/3", "203.0.113.9")},
		[]model.AuthEventLog{event},
	)

	host := findHost(t, hosts, "203.0.113.9")

	if got := host.EscalationCount(); got != 0 {
		t.Errorf("escalations = %d, want 0 for a switch to an ordinary account", got)
	}
}

// A failed escalation is linked like any other event — it is an authentication
// failure from that host — but it is not an escalation.
func TestFailedEscalationCountsAsAFailure(t *testing.T) {
	failed := escalation("5")
	failed.EventType = model.SuFailed
	failed.Success = false

	hosts := Correlate(
		testPorts(),
		nil,
		[]model.UserSession{remoteSession("5", "pts/3", "203.0.113.9")},
		[]model.AuthEventLog{failed},
	)

	host := findHost(t, hosts, "203.0.113.9")

	if got := host.EscalationCount(); got != 0 {
		t.Errorf("escalations = %d, want 0", got)
	}

	if got := host.FailedAuthCount(); got != 1 {
		t.Errorf("failures = %d, want 1", got)
	}

	if got := host.LoginCount(); got != 0 {
		t.Errorf("logins = %d, want 0", got)
	}
}

// Regression: a successful login whose connection and session have both ended
// used to fall back to normal, ranking a break-in below three failed attempts.
func TestSuccessfulLoginStaysCriticalAfterTheSessionEnds(t *testing.T) {
	hosts := Correlate(
		testPorts(),
		nil,
		nil,
		[]model.AuthEventLog{
			authEvent("203.0.113.9", 51000, "root", model.LoginFailed, false),
			authEvent("203.0.113.9", 51001, "root", model.LoginFailed, false),
			authEvent("203.0.113.9", 51002, "root", model.LoginSuccess, true),
		},
	)

	host := findHost(t, hosts, "203.0.113.9")

	if got := host.Concern; got != ConcernCritical {
		t.Errorf("concern = %v, want %v: two failures then a success is a break-in",
			got, ConcernCritical)
	}
}
