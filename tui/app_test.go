package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// Every focus key the README lists has to reach its pane.
func TestPaneFocusKeys(t *testing.T) {
	for _, id := range paneOrder {
		key := paneKeys[id]

		t.Run(key+" focuses "+paneShortTitles[id], func(t *testing.T) {
			m := sizedFixture(160, 48)

			next, _ := m.handleKey(tea.KeyPressMsg{Code: rune(key[0]), Text: key})
			m = next.(model)

			if m.focus != id {
				t.Errorf("focus = %v, want %v", m.focus, id)
			}
		})
	}
}

// Cycling has to wrap in both directions so no pane is unreachable.
func TestPaneCyclingWraps(t *testing.T) {
	tests := []struct {
		name  string
		key   tea.KeyPressMsg
		start paneID
		want  paneID
	}{
		{name: "tab advances", key: tea.KeyPressMsg{Code: tea.KeyTab}, start: panePorts, want: paneConnections},
		{name: "tab wraps at the end", key: tea.KeyPressMsg{Code: tea.KeyTab}, start: paneAuth, want: panePorts},
		{name: "shift+tab goes back", key: tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}, start: paneConnections, want: panePorts},
		{name: "shift+tab wraps at the start", key: tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}, start: panePorts, want: paneAuth},
		{name: "l advances", key: tea.KeyPressMsg{Code: 'l', Text: "l"}, start: panePorts, want: paneConnections},
		{name: "h goes back", key: tea.KeyPressMsg{Code: 'h', Text: "h"}, start: paneConnections, want: panePorts},
		{name: "right advances", key: tea.KeyPressMsg{Code: tea.KeyRight}, start: panePorts, want: paneConnections},
		{name: "left goes back", key: tea.KeyPressMsg{Code: tea.KeyLeft}, start: paneConnections, want: panePorts},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := sizedFixture(160, 48)
			m.focus = tc.start

			next, _ := m.handleKey(tc.key)
			m = next.(model)

			if m.focus != tc.want {
				t.Errorf("focus = %v, want %v", m.focus, tc.want)
			}
		})
	}
}

// There has to be a way out that does not need the mouse.
func TestQuitKeys(t *testing.T) {
	keys := []tea.KeyPressMsg{
		{Code: 'q', Text: "q"},
		{Code: 'c', Mod: tea.ModCtrl},
		{Code: tea.KeyEscape},
	}

	for _, key := range keys {
		m := sizedFixture(160, 48)

		_, cmd := m.handleKey(key)

		if cmd == nil {
			t.Fatalf("key %v produced no command, want quit", key)
		}

		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("key %v did not quit", key)
		}
	}
}

// Navigation keys go to the focused pane, and only to that one.
func TestNavigationReachesOnlyTheFocusedPane(t *testing.T) {
	m := sizedFixture(160, 48)
	m.focus = paneAuth

	next, _ := m.handleKey(tea.KeyPressMsg{Code: 'j', Text: "j"})
	m = next.(model)

	if got := m.tables[paneAuth].cursor; got != 1 {
		t.Errorf("focused pane cursor = %d, want 1", got)
	}

	for _, id := range paneOrder {
		if id == paneAuth {
			continue
		}

		if got := m.tables[id].cursor; got != 0 {
			t.Errorf("pane %v moved its cursor to %d while unfocused", id, got)
		}
	}
}

// The first size message is what turns the default geometry into the real one.
func TestWindowSizeDrivesTheLayout(t *testing.T) {
	m := fixtureModel()

	next, cmd := m.Update(tea.WindowSizeMsg{Width: 200, Height: 60})
	m = next.(model)

	if cmd != nil {
		t.Error("a resize dispatched a command, want none")
	}

	if m.width != 200 || m.height != 60 {
		t.Fatalf("size = %dx%d, want 200x60", m.width, m.height)
	}

	if m.layout.mode != layoutWide {
		t.Errorf("layout mode = %v at 200x60, want wide", m.layout.mode)
	}

	next, _ = m.Update(tea.WindowSizeMsg{Width: 90, Height: 30})
	m = next.(model)

	if m.layout.mode != layoutNarrow {
		t.Errorf("layout mode = %v at 90x30, want narrow", m.layout.mode)
	}
}

// Init has to dispatch the four collectors and arm the first tick, or the
// dashboard starts empty and never fills.
func TestInitStartsThePollingLoop(t *testing.T) {
	m := New().(model)

	if got, want := batchSize(t, m.Init()), 5; got != want {
		t.Errorf("Init dispatched %d commands, want %d (4 collectors + first tick)", got, want)
	}
}

// View is what Bubble Tea renders, and it must agree with render().
func TestViewMatchesRender(t *testing.T) {
	m := sizedFixture(160, 48)

	if got, want := m.View().Content, m.render(); got != want {
		t.Error("View() does not carry what render() produced")
	}
}

// The identity in the header is cosmetic, so a machine that cannot report its
// hostname must render an empty label rather than an error.
func TestLocalHostDegradesQuietly(t *testing.T) {
	t.Setenv("USER", "")

	host := localHost()

	if strings.Contains(host, "@") {
		t.Errorf("localHost() = %q, want no user prefix when USER is unset", host)
	}

	t.Setenv("USER", "alice")

	if got := localHost(); got != "" && !strings.HasPrefix(got, "alice@") {
		t.Errorf("localHost() = %q, want it prefixed with the user", got)
	}
}

// The header counts every source, so the user can see a collector has gone
// quiet without switching to its pane.
func TestHeaderCountsEverySource(t *testing.T) {
	m := sizedFixture(200, 60)

	header := ansi.Strip(m.headerView(200))

	for _, want := range []string{
		countLabel("ports", len(m.ports)),
		countLabel("connections", len(m.connections)),
		countLabel("sessions", len(m.sessions)),
		countLabel("events", len(m.authEvents)),
	} {
		if !strings.Contains(header, want) {
			t.Errorf("header %q is missing %q", header, want)
		}
	}
}

// An error replaces the key hints rather than being appended somewhere off
// screen, and it never overflows the line it is given.
func TestStatusBarErrorFitsAnyWidth(t *testing.T) {
	m := sizedFixture(160, 48)

	next, _ := m.Update(portsLoadedMsg{err: errTooLong})
	m = next.(model)

	for _, width := range []int{200, 120, 80, 40, 10, 1} {
		status := ansi.Strip(m.statusView(width))

		if got := ansi.StringWidth(status); got > width {
			t.Errorf("status bar is %d cells wide at width %d", got, width)
		}
	}
}

// The pane switcher has to stay inside the line even when the hints no longer
// fit beside it.
func TestStatusBarTabsFitAnyWidth(t *testing.T) {
	m := sizedFixture(160, 48)

	for _, width := range []int{200, 120, 80, 60, 40, 20, 1} {
		status := ansi.Strip(m.statusView(width))

		if got := ansi.StringWidth(status); got > width {
			t.Errorf("status bar is %d cells wide at width %d: %q", got, width, status)
		}
	}
}

// errTooLong stands in for a collector error long enough to need truncating.
var errTooLong = errStringer("ss: " + strings.Repeat("something went badly wrong ", 20))

type errStringer string

func (e errStringer) Error() string { return string(e) }
