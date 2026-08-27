package tui

import (
	"errors"
	"testing"
	"time"

	models "github.com/volknichtx/argus/model"

	tea "charm.land/bubbletea/v2"
)

// batchSize reports how many commands a batch holds. Running the outer command
// only unwraps the BatchMsg — the batched commands themselves stay unexecuted,
// so no collector runs and the tick does not block the test for its interval.
// This counts one level, which is why the dispatch batches are kept flat.
func batchSize(t *testing.T, cmd tea.Cmd) int {
	t.Helper()

	if cmd == nil {
		return 0
	}

	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		return 1
	}

	return len(batch)
}

func authEvent(user string) models.AuthEventLog {
	return models.AuthEventLog{
		Timestamp: time.Date(2026, 8, 26, 15, 0, 0, 0, time.UTC),
		Service:   "sshd",
		EventType: models.LoginFailed,
		User:      user,
	}
}

// The loop has to re-arm itself: a tick dispatches the four collectors plus the
// next tick.
func TestTickRefreshesAndReschedules(t *testing.T) {
	m := sizedFixture(160, 48)

	next, cmd := m.Update(tickMsg(time.Now()))
	m = next.(model)

	if got, want := batchSize(t, cmd), 5; got != want {
		t.Fatalf("tick dispatched %d commands, want %d (4 collectors + next tick)", got, want)
	}
}

// A failing collector must not stop the loop.
func TestTickReschedulesDespiteCollectorErrors(t *testing.T) {
	m := sizedFixture(160, 48)

	for _, msg := range []tea.Msg{
		portsLoadedMsg{err: errors.New("ss exploded")},
		connectionsLoadedMsg{err: errors.New("ss exploded")},
		sessionLoadedMsg{err: errors.New("who exploded")},
		authLoadedMsg{err: errors.New("journalctl exploded")},
	} {
		next, _ := m.Update(msg)
		m = next.(model)
	}

	next, cmd := m.Update(tickMsg(time.Now()))
	m = next.(model)

	if got, want := batchSize(t, cmd), 5; got != want {
		t.Fatalf("tick after errors dispatched %d commands, want %d", got, want)
	}
}

// Manual refresh must not arm a second ticker, which would double the poll rate
// on every press.
func TestManualRefreshDoesNotArmSecondTicker(t *testing.T) {
	m := sizedFixture(160, 48)

	_, cmd := m.handleKey(tea.KeyPressMsg{Code: 'r', Text: "r"})

	if got, want := batchSize(t, cmd), 4; got != want {
		t.Fatalf("manual refresh dispatched %d commands, want %d (collectors only)", got, want)
	}
}

func TestAuthCursorAdvancesOnlyOnSuccessfulPoll(t *testing.T) {
	tests := []struct {
		name       string
		start      string
		msg        authLoadedMsg
		wantCursor string
	}{
		{
			name:       "failed poll keeps the cursor",
			start:      "cursor-1",
			msg:        authLoadedMsg{cursor: "cursor-2", err: errors.New("journalctl failed")},
			wantCursor: "cursor-1",
		},
		{
			name:       "empty cursor is refused",
			start:      "cursor-1",
			msg:        authLoadedMsg{cursor: ""},
			wantCursor: "cursor-1",
		},
		{
			name:       "successful poll with events advances",
			start:      "cursor-1",
			msg:        authLoadedMsg{cursor: "cursor-2", events: []models.AuthEventLog{authEvent("root")}},
			wantCursor: "cursor-2",
		},
		{
			// Consumed-but-filtered journal entries move the collector's cursor
			// without producing events; holding it back would re-read them forever.
			name:       "successful poll without events still advances",
			start:      "cursor-1",
			msg:        authLoadedMsg{cursor: "cursor-2"},
			wantCursor: "cursor-2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := sizedFixture(160, 48)
			m.authCursor = tc.start

			next, _ := m.Update(tc.msg)
			m = next.(model)

			if m.authCursor != tc.wantCursor {
				t.Errorf("cursor = %q, want %q", m.authCursor, tc.wantCursor)
			}
		})
	}
}

// Auth is a cursor-based delta, so polls accumulate instead of replacing.
func TestAuthEventsAreAppended(t *testing.T) {
	m := sizedFixture(160, 48)
	before := len(m.authEvents)

	next, _ := m.Update(authLoadedMsg{
		cursor: "cursor-2",
		events: []models.AuthEventLog{authEvent("alice"), authEvent("bob")},
	})
	m = next.(model)

	if got, want := len(m.authEvents), before+2; got != want {
		t.Fatalf("auth events = %d, want %d", got, want)
	}

	if got := m.authEvents[len(m.authEvents)-1].User; got != "bob" {
		t.Errorf("last event user = %q, want %q", got, "bob")
	}

	if got, want := len(m.tables[paneAuth].rows), len(m.authEvents); got != want {
		t.Errorf("auth table rows = %d, want %d", got, want)
	}
}

// Retention is bounded and drops the oldest events first.
func TestAuthEventsAreBounded(t *testing.T) {
	m := sizedFixture(160, 48)
	m.authEvents = nil

	// Two polls that together exceed the cap.
	first := make([]models.AuthEventLog, maxAuthEvents)
	for i := range first {
		first[i] = authEvent("old")
	}

	next, _ := m.Update(authLoadedMsg{cursor: "c1", events: first})
	m = next.(model)

	next, _ = m.Update(authLoadedMsg{cursor: "c2", events: []models.AuthEventLog{authEvent("newest")}})
	m = next.(model)

	if got := len(m.authEvents); got != maxAuthEvents {
		t.Fatalf("retained %d events, want cap of %d", got, maxAuthEvents)
	}

	if got := m.authEvents[len(m.authEvents)-1].User; got != "newest" {
		t.Errorf("newest event was dropped, last user = %q", got)
	}

	if got := m.authEvents[0].User; got != "old" {
		t.Errorf("first retained user = %q, want the oldest survivor", got)
	}

	if got, want := cap(m.authEvents), maxAuthEvents; got > want {
		t.Errorf("backing array kept %d slots, want at most %d", got, want)
	}
}

// Ports, connections and sessions are full snapshots: each poll replaces.
func TestSnapshotPanesReplaceRatherThanAppend(t *testing.T) {
	m := sizedFixture(160, 48)

	next, _ := m.Update(portsLoadedMsg{ports: []models.Port{
		{Protocol: "tcp", Addr: "0.0.0.0", Port: "443", State: "LISTEN", PID: -1},
	}})
	m = next.(model)

	if got := len(m.ports); got != 1 {
		t.Errorf("ports = %d, want 1 (snapshot replaces)", got)
	}

	next, _ = m.Update(connectionsLoadedMsg{connections: nil})
	m = next.(model)

	if got := len(m.connections); got != 0 {
		t.Errorf("connections = %d, want 0 (empty snapshot clears)", got)
	}
}

// A failed poll must surface the error without blanking the pane.
func TestFailedPollKeepsPreviousRows(t *testing.T) {
	m := sizedFixture(160, 48)
	before := len(m.tables[panePorts].rows)

	if before == 0 {
		t.Fatal("fixture should start with port rows")
	}

	next, _ := m.Update(portsLoadedMsg{err: errors.New("ss not found")})
	m = next.(model)

	if got := len(m.tables[panePorts].rows); got != before {
		t.Errorf("rows = %d after failed poll, want %d retained", got, before)
	}

	if m.firstError() == nil {
		t.Error("failed poll did not surface an error")
	}

	// The pane recovers on the next successful poll.
	next, _ = m.Update(portsLoadedMsg{ports: []models.Port{
		{Protocol: "tcp", Addr: "127.0.0.1", Port: "80", State: "LISTEN", PID: -1},
	}})
	m = next.(model)

	if m.errs[panePorts] != nil {
		t.Error("successful poll did not clear the pane error")
	}
}

// One failing collector must not mask the others, and must not silence panes
// that are working.
func TestErrorsAreTrackedPerPane(t *testing.T) {
	m := sizedFixture(160, 48)

	next, _ := m.Update(authLoadedMsg{err: errors.New("journalctl failed")})
	m = next.(model)

	next, _ = m.Update(portsLoadedMsg{ports: []models.Port{{Protocol: "tcp", Addr: "::1", Port: "22", PID: -1}}})
	m = next.(model)

	if m.errs[paneAuth] == nil {
		t.Error("auth error was cleared by an unrelated successful poll")
	}

	if m.errs[panePorts] != nil {
		t.Error("ports pane inherited an unrelated error")
	}

	if m.firstError() == nil {
		t.Error("status bar would show no error while auth is failing")
	}
}
