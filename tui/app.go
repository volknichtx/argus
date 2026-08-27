package tui

import (
	"fmt"
	"os"

	"github.com/volknichtx/argus/correlation"
	models "github.com/volknichtx/argus/model"

	tea "charm.land/bubbletea/v2"
)

type paneID int

// Pane order follows the layout top to bottom: the two raw network panes, the
// correlation of them, then sessions and auth.
const (
	panePorts paneID = iota
	paneConnections
	paneHosts
	paneSessions
	paneAuth

	paneCount = 5
)

var (
	paneOrder = [paneCount]paneID{panePorts, paneConnections, paneHosts, paneSessions, paneAuth}

	paneTitles = [paneCount]string{
		panePorts:       "LISTENING PORTS",
		paneConnections: "ESTABLISHED CONNECTIONS",
		paneHosts:       "CORRELATED HOSTS",
		paneSessions:    "SESSIONS",
		paneAuth:        "AUTH EVENTS",
	}

	paneShortTitles = [paneCount]string{
		panePorts:       "ports",
		paneConnections: "connections",
		paneHosts:       "hosts",
		paneSessions:    "sessions",
		paneAuth:        "auth",
	}

	// "c" for correlation: the a/s/d/f run is full, and the next home-row key
	// would be "g", which is already go-to-top.
	paneKeys = [paneCount]string{
		panePorts:       "a",
		paneConnections: "s",
		paneHosts:       "c",
		paneSessions:    "d",
		paneAuth:        "f",
	}
)

type model struct {
	width  int
	height int
	host   string

	ports       []models.Port
	connections []models.Connection
	sessions    []models.UserSession
	authEvents  []models.AuthEventLog
	authCursor  string

	// hosts is derived from the four slices above, never collected directly.
	hosts []correlation.CorrelatedHost

	// Errors are tracked per pane so a collector that recovers clears its own
	// error, and one that keeps failing does not hide the others.
	errs [paneCount]error

	focus  paneID
	layout layoutDimensions

	tables [paneCount]dataTable
}

func New() tea.Model {
	m := model{
		focus: panePorts,
		host:  localHost(),
		tables: [paneCount]dataTable{
			panePorts:       newTable(portColumns, "no listening ports"),
			paneConnections: newTable(connectionColumns, "no established connections"),
			paneHosts:       newTable(hostColumns, "no correlated hosts"),
			paneSessions:    newTable(sessionColumns, "no active sessions"),
			paneAuth:        newTable(authColumns, "no authentication events"),
		},
	}

	m.relayout()

	return m
}

func (m model) Init() tea.Cmd {
	return m.refreshAndReschedule()
}

// collectorCmds is one command per collector. The collectors shell out to
// ss/who/journalctl, which blocks — running them as commands keeps Update
// instant and lets the results arrive later as messages, so no goroutine ever
// touches the model directly.
func (m model) collectorCmds() []tea.Cmd {
	return []tea.Cmd{
		loadPorts(),
		loadConnections(),
		loadSessions(),
		loadEvents(m.authCursor),
	}
}

// refreshAll polls once without touching the tick schedule.
func (m model) refreshAll() tea.Cmd {
	return tea.Batch(m.collectorCmds()...)
}

// refreshAndReschedule polls and arms the next tick in one flat batch.
func (m model) refreshAndReschedule() tea.Cmd {
	return tea.Batch(append(m.collectorCmds(), scheduleTick())...)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.relayout()

		return m, nil

	case tickMsg:
		// Re-arm unconditionally: the loop must keep running even while a
		// collector is failing.
		return m, m.refreshAndReschedule()

	case portsLoadedMsg:
		// A failed poll keeps the pane's previous rows; only the error is new.
		if msg.err != nil {
			m.errs[panePorts] = fmt.Errorf("ports: %w", msg.err)
			return m, nil
		}

		m.errs[panePorts] = nil
		m.ports = msg.ports
		m.tables[panePorts].setRows(renderRows(m.ports, portToRow))
		m.rebuildDerived()
		m.relayout()

	case connectionsLoadedMsg:
		if msg.err != nil {
			m.errs[paneConnections] = fmt.Errorf("connections: %w", msg.err)
			return m, nil
		}

		m.errs[paneConnections] = nil
		m.connections = msg.connections
		m.rebuildDerived()
		m.relayout()

	case sessionLoadedMsg:
		if msg.err != nil {
			m.errs[paneSessions] = fmt.Errorf("sessions: %w", msg.err)
			return m, nil
		}

		m.errs[paneSessions] = nil
		m.sessions = msg.sessions
		m.tables[paneSessions].setRows(renderRows(m.sessions, sessionToRow))
		m.recorrelate()
		m.relayout()

	case tea.KeyPressMsg:
		return m.handleKey(msg)

	case authLoadedMsg:
		m.applyAuthPoll(msg)
	}

	return m, nil
}

// applyAuthPoll folds one auth poll into the model. Events and cursor move
// together or not at all: on a failed poll neither advances, so the cursor can
// never skip past events that never reached the model.
//
// Note the asymmetry with the events: a successful poll advances the cursor even
// when it yielded no events, because aggregateLog advances its cursor over every
// journal entry it consumed, including the ones filtered out as irrelevant.
// Holding the cursor back there would make each tick re-read and re-parse the
// same growing window of entries forever. An empty cursor is still refused, so
// a poll can never reset us back to the seeding behaviour.
func (m *model) applyAuthPoll(msg authLoadedMsg) {
	if msg.err != nil {
		m.errs[paneAuth] = fmt.Errorf("auth: %w", msg.err)
		return
	}

	m.errs[paneAuth] = nil

	if msg.cursor != "" {
		m.authCursor = msg.cursor
	}

	if len(msg.events) == 0 {
		return
	}

	m.appendAuthEvents(msg.events)
	m.tables[paneAuth].setRows(authRows(m.authEvents))
	m.recorrelate()
	m.relayout()
}

// appendAuthEvents adds the newest delta and drops the oldest entries once the
// retention cap is reached. The trimmed slice is copied so the discarded events
// do not stay reachable through the backing array.
func (m *model) appendAuthEvents(events []models.AuthEventLog) {
	m.authEvents = append(m.authEvents, events...)

	if len(m.authEvents) <= maxAuthEvents {
		return
	}

	trimmed := make([]models.AuthEventLog, maxAuthEvents)
	copy(trimmed, m.authEvents[len(m.authEvents)-maxAuthEvents:])

	m.authEvents = trimmed
}

// rebuildDerived refreshes everything computed from more than one source: the
// connection rows (whose direction depends on the listening ports) and the
// correlation. Both are recomputed rather than cached, so neither can drift
// from the collectors' data.
func (m *model) rebuildDerived() {
	m.tables[paneConnections].setRows(connectionRows(m.connections, m.ports))
	m.recorrelate()
}

// recorrelate rebuilds the correlation pane from the model's current data.
//
// It is recomputed from the four source slices rather than kept as a cached
// derivative, so the pane can never drift from the panes it summarises — the
// collectors' data stays the single source of truth.
func (m *model) recorrelate() {
	m.hosts = correlation.Correlate(m.ports, m.connections, m.sessions, m.authEvents)
	m.tables[paneHosts].setRows(renderRows(m.hosts, hostToRow))
}

// firstError reports the error to surface in the status bar, preferring the
// focused pane so the message matches what the user is looking at.
func (m model) firstError() error {
	if err := m.errs[m.focus]; err != nil {
		return err
	}

	for _, id := range paneOrder {
		if err := m.errs[id]; err != nil {
			return err
		}
	}

	return nil
}

func (m model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c", "esc":
		return m, tea.Quit

	case "a":
		m.focus = panePorts
		return m, nil

	case "s":
		m.focus = paneConnections
		return m, nil

	case "c":
		m.focus = paneHosts
		return m, nil

	case "d":
		m.focus = paneSessions
		return m, nil

	case "f":
		m.focus = paneAuth
		return m, nil

	case "tab", "right", "l":
		m.focus = (m.focus + 1) % paneCount
		return m, nil

	case "shift+tab", "left", "h":
		m.focus = (m.focus + paneCount - 1) % paneCount
		return m, nil

	case "r":
		// Refresh now without arming a tick: scheduleTick here would add a
		// second ticker on every press, doubling the poll rate each time.
		return m, m.refreshAll()
	}

	m.tables[m.focus].handleKey(msg)

	return m, nil
}

func (m model) table(id paneID) dataTable {
	return m.tables[id]
}

// relayout recomputes the layout from the current terminal size and row counts,
// then hands every table its exact viewport. Row counts feed back into the
// layout so panes only claim the height their content needs.
func (m *model) relayout() {
	width, height := m.width, m.height

	// Data can arrive before the first WindowSizeMsg; size the tables against
	// the default geometry until the terminal reports its real dimensions.
	if width == 0 || height == 0 {
		width, height = defaultWidth, defaultHeight
	}

	m.layout = calculateLayout(width, height, m.rowCounts())
	m.sizeTables(m.layout)
}

func (m *model) sizeTables(l layoutDimensions) {
	if l.mode == layoutNarrow {
		width, rows := tableWidth(l.contentWidth), tableRows(l.focusHeight)

		for i := range m.tables {
			m.tables[i].setSize(width, rows)
		}

		return
	}

	m.tables[panePorts].setSize(
		tableWidth(l.portsWidth),
		tableRows(l.topHeight),
	)

	m.tables[paneConnections].setSize(
		tableWidth(l.connectionsWidth),
		tableRows(l.topHeight),
	)

	m.tables[paneHosts].setSize(
		tableWidth(l.contentWidth),
		tableRows(l.hostsHeight),
	)

	m.tables[paneSessions].setSize(
		tableWidth(l.contentWidth),
		tableRows(l.sessionsHeight),
	)

	m.tables[paneAuth].setSize(
		tableWidth(l.contentWidth),
		tableRows(l.authHeight),
	)
}

func (m model) rowCounts() rowCounts {
	return rowCounts{
		ports:       len(m.tables[panePorts].rows),
		connections: len(m.tables[paneConnections].rows),
		hosts:       len(m.tables[paneHosts].rows),
		sessions:    len(m.tables[paneSessions].rows),
		auth:        len(m.tables[paneAuth].rows),
	}
}

func tableWidth(paneWidth int) int {
	return maxInt(1, paneWidth-paneHorizontalFrame)
}

func tableRows(paneHeight int) int {
	return maxInt(1, paneHeight-paneChrome)
}

func localHost() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return ""
	}

	if user := os.Getenv("USER"); user != "" {
		return user + "@" + host
	}

	return host
}
