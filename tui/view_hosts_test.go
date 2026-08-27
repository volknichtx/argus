package tui

import (
	"net"
	"strings"
	"testing"

	"github.com/volknichtx/argus/correlation"
	models "github.com/volknichtx/argus/model"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestToneForConcern(t *testing.T) {
	tests := []struct {
		name    string
		concern correlation.Concern
		want    tone
	}{
		{name: "critical", concern: correlation.ConcernCritical, want: toneDanger},
		{name: "elevated", concern: correlation.ConcernElevated, want: toneWarn},
		{name: "normal", concern: correlation.ConcernNormal, want: toneMuted},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := toneForConcern(tc.concern); got != tc.want {
				t.Errorf("toneForConcern(%v) = %v, want %v", tc.concern, got, tc.want)
			}
		})
	}
}

// The row is a projection of the engine's output: every signal it counted has
// to be visible, and empty signals must read as absent rather than as zero.
func TestHostToRowShowsEverySignal(t *testing.T) {
	hosts := correlation.Correlate(
		[]models.Port{{Protocol: "tcp", Addr: "0.0.0.0", Port: "22", State: "LISTEN", PID: -1}},
		[]models.Connection{{
			Protocol: "tcp", LocalAddr: "10.0.0.10", LocalPort: "22",
			RemoteAddr: "10.0.0.20", RemotePort: "64985", State: "ESTAB", PID: -1,
		}},
		[]models.UserSession{{User: "alice", TTY: "pts/2", Source: "10.0.0.20", PID: 5832}},
		[]models.AuthEventLog{{
			Service: "sshd", EventType: models.LoginSuccess, User: "alice",
			SourceIP: net.ParseIP("10.0.0.20"), SourcePort: 64985, Success: true,
		}},
	)

	if len(hosts) != 1 {
		t.Fatalf("expected one correlated host, got %d", len(hosts))
	}

	r := hostToRow(hosts[0])

	if got, want := len(r), len(hostColumns(160)); got != want {
		t.Fatalf("row has %d cells, table has %d columns", got, want)
	}

	joined := make([]string, len(r))
	for i, c := range r {
		joined[i] = c.text
	}

	text := strings.Join(joined, " | ")

	// Inbound on a listener plus an authentication is the full access chain, so
	// this LAN peer is critical, not merely elevated.
	for _, want := range []string{"10.0.0.20", "CRITICAL", "→ :22", "alice"} {
		if !strings.Contains(text, want) {
			t.Errorf("row %q is missing %q", text, want)
		}
	}

	// Outbound is genuinely absent here and must not read as a count.
	if got := r[3].text; got != unknownValue {
		t.Errorf("outbound cell = %q, want %q for no connections", got, unknownValue)
	}
}

// A critical host must carry the danger tone across the row, not on one cell.
func TestHostToRowTonesWholeRowByConcern(t *testing.T) {
	host := correlation.CorrelatedHost{
		IP:      net.ParseIP("203.0.113.9"),
		Address: "203.0.113.9",
		Concern: correlation.ConcernCritical,
		AuthEvents: []models.AuthEventLog{
			{User: "root", EventType: models.LoginFailed},
			{User: "root", EventType: models.LoginFailed},
			{User: "root", EventType: models.LoginFailed},
		},
	}

	for i, c := range hostToRow(host) {
		if c.text == unknownValue {
			continue
		}

		if c.tone != toneDanger {
			t.Errorf("cell %d (%q) has tone %v, want %v", i, c.text, c.tone, toneDanger)
		}
	}
}

// The pane behaves like the others: focus, position hint, empty state.
func TestCorrelationPaneIntegrates(t *testing.T) {
	m := sizedFixture(200, 60)

	if len(m.tables[paneHosts].rows) == 0 {
		t.Fatal("fixture produced no correlated hosts")
	}

	out := m.render()

	if !strings.Contains(out, paneTitles[paneHosts]) {
		t.Error("correlation pane is not rendered in the wide layout")
	}

	// Focus via its key, then navigate.
	next, _ := m.handleKey(tea.KeyPressMsg{Code: 'c', Text: "c"})
	m = next.(model)

	if m.focus != paneHosts {
		t.Fatalf("focus = %v, want %v", m.focus, paneHosts)
	}

	if hint := m.tables[paneHosts].positionHint(); hint == "" {
		t.Error("correlation pane has no position hint")
	}

	next, _ = m.handleKey(tea.KeyPressMsg{Code: 'G', Text: "G", Mod: tea.ModShift})
	m = next.(model)

	if got, want := m.tables[paneHosts].cursor, len(m.hosts)-1; got != want {
		t.Errorf("cursor = %d, want %d", got, want)
	}

	// The status bar must advertise the new pane.
	status := m.statusView(200)
	if !strings.Contains(ansi.Strip(status), "c hosts") {
		t.Errorf("status bar does not list the correlation pane: %q", ansi.Strip(status))
	}
}

// An empty correlation renders its message instead of crashing.
func TestCorrelationPaneEmpty(t *testing.T) {
	m := sizedFixture(200, 60)
	m.ports = nil
	m.connections = nil
	m.sessions = nil
	m.authEvents = nil
	m.recorrelate()
	m.relayout()

	out := m.render()

	if !strings.Contains(out, "no correlated hosts") {
		t.Error("empty correlation pane does not render its message")
	}
}

// The pane must never drift from the source panes: it is recomputed, not cached.
func TestCorrelationFollowsSourceData(t *testing.T) {
	m := sizedFixture(200, 60)

	next, _ := m.Update(connectionsLoadedMsg{connections: []models.Connection{{
		Protocol: "tcp", LocalAddr: "10.0.0.10", LocalPort: "45192",
		RemoteAddr: "203.0.113.77", RemotePort: "443", State: "ESTAB", PID: -1,
	}}})
	m = next.(model)

	found := false
	for _, host := range m.hosts {
		if host.Address == "203.0.113.77" {
			found = true
		}
	}

	if !found {
		t.Error("a new connection did not appear in the correlation")
	}

	// Clearing the source data must clear the derived host too.
	next, _ = m.Update(connectionsLoadedMsg{connections: nil})
	m = next.(model)

	for _, host := range m.hosts {
		if host.Address == "203.0.113.77" {
			t.Error("correlation kept a host whose connection is gone")
		}
	}
}

// Regression: who(1) reports "local" for local sessions, so a non-empty check
// would flag every one of them as remote.
func TestLocalSessionsAreNotFlaggedRemote(t *testing.T) {
	local := sessionToRow(models.UserSession{User: "alice", TTY: "tty1", Source: "local", PID: 1291})

	if got := local[5].tone; got != toneMuted {
		t.Errorf("local session source tone = %v, want %v", got, toneMuted)
	}

	remote := sessionToRow(models.UserSession{User: "alice", TTY: "pts/2", Source: "10.0.0.20", PID: 5832})

	if got := remote[5].tone; got != toneWarn {
		t.Errorf("remote session source tone = %v, want %v", got, toneWarn)
	}
}

// The ROOT column is the whole point of the escalation join: when someone logs
// in over ssh and becomes root, that has to be visible on the host's row rather
// than only as an unattributed line in the auth pane.
func TestRootColumnShowsTheEscalation(t *testing.T) {
	const rootColumn = 7

	columns := hostColumns(200)
	if got := columns[rootColumn].title; got != "ROOT" {
		t.Fatalf("column %d is %q, want ROOT", rootColumn, got)
	}

	hosts := correlation.Correlate(
		[]models.Port{{Protocol: "tcp", Addr: "0.0.0.0", Port: "22", State: "LISTEN", PID: -1}},
		nil,
		[]models.UserSession{{User: "alice", TTY: "pts/3", Source: "10.0.0.20", PID: 5832, ID: "5"}},
		[]models.AuthEventLog{
			{
				Service: "sshd", EventType: models.LoginSuccess, User: "alice",
				SourceIP: net.ParseIP("10.0.0.20"), SourcePort: 51000, Success: true,
			},
			{
				Service: "su", EventType: models.SuSuccess, User: "root",
				TargetUser: "root", AuditSession: "5", Success: true,
			},
		},
	)

	if len(hosts) != 1 {
		t.Fatalf("expected one correlated host, got %d", len(hosts))
	}

	if got := hostToRow(hosts[0])[rootColumn].text; got != "1" {
		t.Errorf("ROOT cell = %q, want 1", got)
	}

	// A host that never escalated must read as absent, not as a zero.
	quiet := correlation.CorrelatedHost{IP: net.ParseIP("10.0.0.30"), Address: "10.0.0.30"}

	if got := hostToRow(quiet)[rootColumn].text; got != unknownValue {
		t.Errorf("ROOT cell = %q, want %q for a host that never escalated", got, unknownValue)
	}
}

// A privilege change is not a login. One ssh session that ran su twice is one
// login, or the LOGINS column would inflate every time someone used sudo.
func TestLoginsColumnExcludesPrivilegeChanges(t *testing.T) {
	const loginsColumn = 5

	if got := hostColumns(200)[loginsColumn].title; got != "LOGINS" {
		t.Fatalf("column %d is %q, want LOGINS", loginsColumn, got)
	}

	host := correlation.CorrelatedHost{
		IP:      net.ParseIP("10.0.0.20"),
		Address: "10.0.0.20",
		AuthEvents: []models.AuthEventLog{
			{EventType: models.LoginSuccess, User: "alice", Success: true},
			{EventType: models.SuSuccess, User: "root", TargetUser: "root", Success: true},
			{EventType: models.SudoSuccess, User: "alice", TargetUser: "root", Success: true},
		},
	}

	if got := hostToRow(host)[loginsColumn].text; got != "1" {
		t.Errorf("LOGINS cell = %q, want 1: two privilege changes are not two logins", got)
	}
}
