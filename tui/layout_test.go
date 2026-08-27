package tui

import (
	"net"
	"strings"
	"testing"
	"time"

	models "github.com/volknichtx/argus/model"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func fixtureModel() model {
	m := New().(model)

	m.ports = []models.Port{
		{Protocol: "tcp", Addr: "0.0.0.0", Port: "22", State: "LISTEN", PID: -1, Process: "undefined"},
		{Protocol: "tcp", Addr: "127.0.0.1", Port: "11434", State: "LISTEN", PID: 1337, Process: "appserver"},
		{Protocol: "udp", Addr: "*", Port: "42473", State: "UNCONN", PID: 3788, Process: "webbrowser"},
	}

	m.connections = []models.Connection{
		{Protocol: "tcp", LocalAddr: "10.0.0.10", LocalPort: "33570", RemoteAddr: "198.51.100.93", RemotePort: "443", State: "ESTAB", PID: 3788, Process: "webbrowser"},
		{Protocol: "tcp", LocalAddr: "127.0.0.1", LocalPort: "50102", RemoteAddr: "127.0.0.1", RemotePort: "11434", State: "ESTAB", PID: 1337, Process: "appserver"},
	}

	m.sessions = []models.UserSession{
		{User: "alice", TTY: "tty1", LoginDate: "2026-08-26", LoginTime: "09:07", Idle: "05:42", PID: 1291, Source: "local"},
		{User: "alice", TTY: "pts/2", LoginDate: "2026-08-26", LoginTime: "14:32", Idle: ".", PID: 5832, Source: "10.0.0.20"},
	}

	m.authEvents = []models.AuthEventLog{
		{
			Timestamp:  time.Date(2026, 8, 26, 14, 32, 37, 0, time.UTC),
			Service:    "sshd",
			EventType:  models.LoginSuccess,
			User:       "alice",
			SourceIP:   net.ParseIP("10.0.0.20"),
			SourcePort: 64985,
			Success:    true,
		},
		{
			Timestamp: time.Date(2026, 8, 26, 14, 30, 11, 0, time.UTC),
			Service:   "sshd",
			EventType: models.InvalidUser,
			User:      "admin",
			SourceIP:  net.ParseIP("203.0.113.9"),
		},
	}

	m.tables[panePorts].setRows(renderRows(m.ports, portToRow))
	m.tables[paneSessions].setRows(renderRows(m.sessions, sessionToRow))
	m.tables[paneAuth].setRows(authRows(m.authEvents))
	m.rebuildDerived()

	return m
}

func sizedFixture(width, height int) model {
	m := fixtureModel()
	m.width = width
	m.height = height
	m.relayout()

	return m
}

// The whole dashboard has to fit the terminal exactly: never taller than the
// screen, never wider, at any size.
func TestRenderFitsTerminal(t *testing.T) {
	sizes := []struct{ width, height int }{
		{80, 24},
		{100, 30},
		{120, 30},
		{160, 48},
		{200, 60},
		{240, 100},
		{64, 16},
		{111, 40},
		{112, 40},
		{160, 20},
		{200, 21},
	}

	for _, size := range sizes {
		m := sizedFixture(size.width, size.height)
		out := m.render()

		lines := strings.Split(out, "\n")

		if len(lines) > size.height {
			t.Errorf("%dx%d: rendered %d lines, terminal has %d",
				size.width, size.height, len(lines), size.height)
		}

		for i, line := range lines {
			if w := ansi.StringWidth(line); w > size.width {
				t.Errorf("%dx%d: line %d is %d cells wide, terminal has %d",
					size.width, size.height, i, w, size.width)
			}
		}
	}
}

// A pane with two rows must not reserve a third of the screen.
func TestPanesShrinkToContent(t *testing.T) {
	m := sizedFixture(200, 60)

	if got, want := m.layout.sessionsHeight, len(m.sessions)+paneChrome; got != want {
		t.Errorf("sessions pane height = %d, want %d", got, want)
	}

	if got, want := m.layout.authHeight, len(m.authEvents)+paneChrome; got != want {
		t.Errorf("auth pane height = %d, want %d", got, want)
	}
}

// Below the wide breakpoint only the focused pane is drawn.
func TestNarrowLayoutShowsFocusedPaneOnly(t *testing.T) {
	m := sizedFixture(90, 30)

	if m.layout.mode != layoutNarrow {
		t.Fatalf("layout mode = %v, want narrow", m.layout.mode)
	}

	out := m.render()

	if !strings.Contains(out, paneTitles[panePorts]) {
		t.Errorf("focused pane title missing from narrow view")
	}

	if strings.Contains(out, paneTitles[paneConnections]) {
		t.Errorf("unfocused pane rendered in narrow view")
	}
}

// The cursor highlight has to cover the full row width, including cells that
// carry their own color. Regression guard for the selection being applied on
// top of pre-styled cells.
func TestCursorHighlightSpansWholeRow(t *testing.T) {
	m := sizedFixture(160, 48)
	table := m.tables[panePorts]

	line := table.rowLine(table.rows[0], true, true)

	if got := ansi.StringWidth(line); got != table.width {
		t.Fatalf("selected row width = %d, want %d", got, table.width)
	}

	segments := strings.Split(line, "\x1b[")

	for _, segment := range segments[1:] {
		if strings.HasPrefix(segment, "m") || strings.HasPrefix(segment, "0m") {
			continue
		}

		content := segment[strings.Index(segment, "m")+1:]
		if strings.TrimSpace(content) == "" {
			continue
		}

		if !strings.Contains(segment[:strings.Index(segment, "m")], "48;") {
			t.Fatalf("segment %q has no background: highlight would break", segment)
		}
	}
}

func TestKeysSwitchPanesAndMoveCursor(t *testing.T) {
	m := sizedFixture(160, 48)

	next, _ := m.handleKey(tea.KeyPressMsg{Code: 's', Text: "s"})
	m = next.(model)

	if m.focus != paneConnections {
		t.Fatalf("focus = %v, want connections", m.focus)
	}

	next, _ = m.handleKey(tea.KeyPressMsg{Code: 'j', Text: "j"})
	m = next.(model)

	if got := m.tables[paneConnections].cursor; got != 1 {
		t.Fatalf("cursor = %d, want 1", got)
	}

	next, _ = m.handleKey(tea.KeyPressMsg{Code: 'G', Text: "G", Mod: tea.ModShift})
	m = next.(model)

	if got, want := m.tables[paneConnections].cursor, len(m.connections)-1; got != want {
		t.Fatalf("cursor = %d, want %d", got, want)
	}
}
