package collect

import (
	"testing"
)

const loginctlJSON = `[{"session":"2","uid":1000,"user":"alice","seat":"seat0","leader":1236,"class":"user","tty":"tty1","idle":false,"since":null},` +
	`{"session":"3","uid":1000,"user":"alice","seat":null,"leader":1242,"class":"manager","tty":null,"idle":false,"since":null},` +
	`{"session":"5","uid":1000,"user":"alice","seat":null,"leader":83143,"class":"user","tty":"pts/3","idle":false,"since":null}]`

// who says who is logged in and from where; logind says which session that is.
// Both halves are needed before a privilege change can be traced back to a host.
func TestSessionCollectorAttachesLogindIdentifiers(t *testing.T) {
	run := fakeCommands(t, map[string]fakeResult{
		"who": {stdout: "alice tty1 2026-08-27 09:02 00:49 1293\n" +
			"alice pts/3 2026-08-27 09:53 . 78653 (192.0.2.20)\n"},
		"loginctl": {stdout: loginctlJSON},
	})

	sessions, err := SessionCollector()
	if err != nil {
		t.Fatalf("SessionCollector(): %v", err)
	}

	if !run.ranProgram("loginctl") {
		t.Fatalf("logind was never asked for session ids: %v", run.runs)
	}

	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}

	if got := sessions[0].ID; got != "2" {
		t.Errorf("tty1 session id = %q, want 2", got)
	}

	if got := sessions[1].ID; got != "5" {
		t.Errorf("pts/3 session id = %q, want 5", got)
	}

	if got := sessions[1].Source; got != "192.0.2.20" {
		t.Errorf("pts/3 source = %q, want 192.0.2.20", got)
	}
}

// logind is an enrichment, not a dependency. Losing it costs the link between a
// privilege change and its origin; it must not cost the sessions pane.
func TestSessionCollectorSurvivesWithoutLogind(t *testing.T) {
	tests := []struct {
		name     string
		loginctl fakeResult
	}{
		{name: "loginctl missing or failing", loginctl: fakeResult{exitCode: 1}},
		{name: "loginctl too old for --json", loginctl: fakeResult{stdout: "SESSION UID USER\n2 1000 alice\n"}},
		{name: "loginctl returns nothing", loginctl: fakeResult{stdout: ""}},
		{name: "loginctl returns an empty list", loginctl: fakeResult{stdout: "[]"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeCommands(t, map[string]fakeResult{
				"who":      {stdout: "alice pts/3 2026-08-27 09:53 . 78653 (192.0.2.20)\n"},
				"loginctl": tc.loginctl,
			})

			sessions, err := SessionCollector()
			if err != nil {
				t.Fatalf("SessionCollector(): %v", err)
			}

			if len(sessions) != 1 {
				t.Fatalf("sessions = %d, want the who row to survive", len(sessions))
			}

			if sessions[0].ID != "" {
				t.Errorf("session id = %q, want none to be invented", sessions[0].ID)
			}

			if sessions[0].Source != "192.0.2.20" {
				t.Errorf("source = %q, want it unaffected", sessions[0].Source)
			}
		})
	}
}

// A terminal claimed by two sessions cannot identify either of them, and a
// wrong identifier would attribute root to the wrong login.
func TestDuplicateTTYYieldsNoIdentifier(t *testing.T) {
	byTTY := loginSessionsFrom(t, `[{"session":"5","tty":"pts/3"},{"session":"6","tty":"pts/3"}]`)

	if got := byTTY["pts/3"]; got != "" {
		t.Errorf("pts/3 resolved to session %q, want no identifier", got)
	}
}

// Sessions logind knows but that own no terminal cannot be matched to a who row.
func TestSessionsWithoutTTYAreIgnored(t *testing.T) {
	byTTY := loginSessionsFrom(t, `[{"session":"3","tty":null},{"session":"5","tty":"pts/3"}]`)

	if len(byTTY) != 1 || byTTY["pts/3"] != "5" {
		t.Errorf("mapping = %v, want only pts/3 -> 5", byTTY)
	}
}

// loginSessionsFrom runs loginSessionsByTTY against canned loginctl output.
func loginSessionsFrom(t *testing.T, output string) map[string]string {
	t.Helper()

	fakeCommands(t, map[string]fakeResult{"loginctl": {stdout: output}})

	return loginSessionsByTTY()
}
