package tui

import (
	"time"

	"github.com/volknichtx/argus/collect"
	models "github.com/volknichtx/argus/model"

	tea "charm.land/bubbletea/v2"
)

// refreshInterval is how often every collector is re-run. All four together
// take roughly 35ms, so a single shared interval is plenty; splitting the
// slow-changing panes onto their own cadence would buy nothing.
const refreshInterval = 2 * time.Second

// maxAuthEvents bounds the retained auth log. Journald only returns the delta
// after the cursor, so the list would otherwise grow for the whole session.
const maxAuthEvents = 500

type tickMsg time.Time

type portsLoadedMsg struct {
	ports []models.Port
	err   error
}

type connectionsLoadedMsg struct {
	connections []models.Connection
	err         error
}

type sessionLoadedMsg struct {
	sessions []models.UserSession
	err      error
}

type authLoadedMsg struct {
	events []models.AuthEventLog
	cursor string
	err    error
}

// scheduleTick arms the next refresh. tea.Tick fires once, so every tickMsg
// handler has to call this again or the loop stops after one iteration.
func scheduleTick() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func loadPorts() tea.Cmd {
	return func() tea.Msg {
		ports, err := collect.PortCollector()

		return portsLoadedMsg{
			ports: ports,
			err:   err,
		}
	}
}

func loadConnections() tea.Cmd {
	return func() tea.Msg {
		connections, err := collect.ConnectionCollector()

		return connectionsLoadedMsg{
			connections: connections,
			err:         err,
		}
	}
}

func loadSessions() tea.Cmd {
	return func() tea.Msg {
		sessions, err := collect.SessionCollector()

		return sessionLoadedMsg{
			sessions: sessions,
			err:      err,
		}
	}
}

// loadEvents polls journald for everything after the cursor we last stored. An
// empty cursor seeds from the most recent journal entries instead.
func loadEvents(afterCursor string) tea.Cmd {
	return func() tea.Msg {
		events, cursor, err := collect.CollectAuthEvents(afterCursor)

		return authLoadedMsg{
			events: events,
			cursor: cursor,
			err:    err,
		}
	}
}
