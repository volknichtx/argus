package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	defaultWidth  = 160
	defaultHeight = 48

	horizontalPadding = 1
	paneGap           = 2

	minTerminalWidth  = 64
	minTerminalHeight = 16

	// Below this width the two-column layout no longer holds a readable table,
	// so the focused pane takes over the screen instead.
	wideLayoutWidth = 112

	// Header, the blank line under it, one blank line between each of the four
	// stacked blocks, and the status bar.
	wideChromeRows = 7
	// Header, blank line, blank line, status bar.
	narrowChromeRows = 4

	minPaneHeight = paneChrome + 1
	// Four stacked blocks plus the chrome around them. Below this the panes
	// would be too short to be useful, so the focused-pane fallback takes over.
	minWideHeight = minPaneHeight*4 + wideChromeRows
)

type layoutMode int

const (
	layoutWide layoutMode = iota
	layoutNarrow
)

type layoutDimensions struct {
	mode         layoutMode
	contentWidth int

	portsWidth       int
	connectionsWidth int

	topHeight      int
	hostsHeight    int
	sessionsHeight int
	authHeight     int

	// Height of the single visible pane in narrow mode.
	focusHeight int
}

// rowCounts is how many data rows each pane currently holds. The layout uses it
// so a pane with two rows does not reserve a third of the screen.
type rowCounts struct {
	ports       int
	connections int
	hosts       int
	sessions    int
	auth        int
}

func calculateLayout(width, height int, counts rowCounts) layoutDimensions {
	contentWidth := maxInt(1, width-horizontalPadding*2)

	// Too narrow for two readable tables side by side, or too short to stack
	// three panes: fall back to showing the focused pane full screen.
	if width < wideLayoutWidth || height < minWideHeight {
		return layoutDimensions{
			mode:         layoutNarrow,
			contentWidth: contentWidth,
			focusHeight:  maxInt(minPaneHeight, height-narrowChromeRows),
		}
	}

	topAvailableWidth := maxInt(2, contentWidth-paneGap)
	portsWidth := topAvailableWidth * 42 / 100
	connectionsWidth := topAvailableWidth - portsWidth

	available := height - wideChromeRows

	// The stacked panes take exactly the height their content needs, each capped
	// so one long list cannot crowd out the rest. Ports and connections are the
	// lists that actually grow, so the top row absorbs everything left over
	// instead of every pane getting a fixed share of the screen.
	hostsHeight := fitHeight(counts.hosts, available*30/100)
	sessionsHeight := fitHeight(counts.sessions, available*20/100)
	authHeight := fitHeight(counts.auth, available*30/100)

	stacked := []*int{&authHeight, &hostsHeight, &sessionsHeight}
	topHeight := available - hostsHeight - sessionsHeight - authHeight

	// Reclaim height from the stacked panes, largest concession first, until the
	// top row clears its minimum.
	for topHeight < minPaneHeight {
		shrunk := false

		for _, height := range stacked {
			if *height > minPaneHeight {
				*height--
				shrunk = true

				break
			}
		}

		topHeight = available - hostsHeight - sessionsHeight - authHeight

		if !shrunk {
			topHeight = minPaneHeight
			break
		}
	}

	return layoutDimensions{
		mode:             layoutWide,
		contentWidth:     contentWidth,
		portsWidth:       portsWidth,
		connectionsWidth: connectionsWidth,
		topHeight:        topHeight,
		hostsHeight:      hostsHeight,
		sessionsHeight:   sessionsHeight,
		authHeight:       authHeight,
	}
}

// fitHeight is the pane height needed for n rows, never below one row and never
// above the given limit.
func fitHeight(rows, limit int) int {
	return clampInt(rows+paneChrome, minPaneHeight, maxInt(minPaneHeight, limit))
}

func (m model) View() tea.View {
	return tea.NewView(m.render())
}

func (m model) render() string {
	if m.width == 0 || m.height == 0 {
		return ""
	}

	if m.width < minTerminalWidth || m.height < minTerminalHeight {
		return m.tooSmallView()
	}

	l := m.layout

	body := m.wideBody(l)
	if l.mode == layoutNarrow {
		body = m.narrowBody(l)
	}

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		m.headerView(l.contentWidth),
		"",
		body,
	)

	// Pin the status bar to the bottom edge so leftover height ends up as calm
	// empty space rather than oversized panes.
	filler := maxInt(1, m.height-lipgloss.Height(content)-1)

	return lipgloss.NewStyle().
		Padding(0, horizontalPadding).
		Render(content + strings.Repeat("\n", filler) + m.statusView(l.contentWidth))
}

func (m model) wideBody(l layoutDimensions) string {
	topRow := lipgloss.JoinHorizontal(
		lipgloss.Top,
		m.paneView(panePorts, l.portsWidth, l.topHeight),
		strings.Repeat(" ", paneGap),
		m.paneView(paneConnections, l.connectionsWidth, l.topHeight),
	)

	return lipgloss.JoinVertical(
		lipgloss.Left,
		topRow,
		"",
		m.paneView(paneHosts, l.contentWidth, l.hostsHeight),
		"",
		m.paneView(paneSessions, l.contentWidth, l.sessionsHeight),
		"",
		m.paneView(paneAuth, l.contentWidth, l.authHeight),
	)
}

func (m model) narrowBody(l layoutDimensions) string {
	return m.paneView(m.focus, l.contentWidth, l.focusHeight)
}

func (m model) paneView(id paneID, width, height int) string {
	t := m.table(id)
	focused := m.focus == id

	return renderPane(
		paneTitles[id],
		t.positionHint(),
		t.view(focused),
		width,
		height,
		focused,
	)
}

// headerView is the top line: identity on the left, per-pane counts on the right.
func (m model) headerView(width int) string {
	left := appNameStyle.Render("ATTACK SURFACE")

	if host := m.host; host != "" {
		left += headerMetaStyle.Render("   " + host)
	}

	counts := headerCountStyle.Render(
		joinDot(
			countLabel("ports", len(m.ports)),
			countLabel("connections", len(m.connections)),
			countLabel("sessions", len(m.sessions)),
			countLabel("events", len(m.authEvents)),
		),
	)

	return spread(left, counts, width)
}

// statusView doubles as the pane switcher: the active pane is highlighted, so
// narrow mode still shows where you are.
func (m model) statusView(width int) string {
	if err := m.firstError(); err != nil {
		return errorStyle.Render(
			ansi.Truncate("error: "+err.Error(), maxInt(1, width), "…"),
		)
	}

	tabs := make([]string, 0, len(paneOrder))

	for _, id := range paneOrder {
		key, label := paneKeys[id], paneShortTitles[id]

		if m.focus == id {
			tabs = append(tabs, statusActiveStyle.Render(key+" "+label))
			continue
		}

		tabs = append(tabs, statusKeyStyle.Render(key)+statusLabelStyle.Render(" "+label))
	}

	left := strings.Join(tabs, statusSepStyle.Render("   "))

	// Shorten the key hints rather than dropping them the moment space is tight.
	variants := []string{
		joinDot("j/k move", "g/G first/last", "tab next pane", "r refresh", "q quit"),
		joinDot("j/k", "g/G", "tab", "r", "q quit"),
	}

	for _, variant := range variants {
		hints := statusLabelStyle.Render(variant)

		if ansi.StringWidth(left)+ansi.StringWidth(hints)+3 <= width {
			return spread(left, hints, width)
		}
	}

	return ansi.Truncate(left, maxInt(1, width), "…")
}

func (m model) tooSmallView() string {
	message := lipgloss.JoinVertical(
		lipgloss.Center,
		appNameStyle.Render("ATTACK SURFACE"),
		"",
		emptyStyle.Render("terminal too small"),
		headerMetaStyle.Render(
			formatSize(minTerminalWidth, minTerminalHeight)+" required, "+
				formatSize(m.width, m.height)+" available",
		),
	)

	return lipgloss.NewStyle().
		Width(maxInt(1, m.width)).
		Height(maxInt(1, m.height)).
		AlignHorizontal(lipgloss.Center).
		AlignVertical(lipgloss.Center).
		Render(message)
}

// spread pushes left and right to opposite ends of a line of the given width,
// dropping the right side when there is no room for both.
func spread(left, right string, width int) string {
	gap := width - ansi.StringWidth(left) - ansi.StringWidth(right)

	if gap < 1 {
		return ansi.Truncate(left, maxInt(1, width), "…")
	}

	return left + strings.Repeat(" ", gap) + right
}

func joinDot(parts ...string) string {
	return strings.Join(parts, "  ·  ")
}

func countLabel(label string, n int) string {
	return label + " " + itoa(n)
}
