package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	// Width of the cursor gutter in front of every row.
	cursorGutterWidth = 2

	cursorMarker = "▍"
)

// cell is a single table value plus the meaning of that value. Text stays free
// of escape sequences until the table renders it, so selection, truncation and
// alignment all operate on plain strings.
type cell struct {
	text string
	tone tone
}

type row []cell

func txt(value string) cell {
	return cell{text: value}
}

func dim(value string) cell {
	return cell{text: value, tone: toneMuted}
}

func toned(value string, t tone) cell {
	return cell{text: value, tone: t}
}

// dataTable is a compact, self-rendering table. It replaces bubbles/table
// because that widget applies the selection style as an outer wrapper around an
// already styled row, which drops the highlight as soon as a cell carries its
// own color.
type dataTable struct {
	columnsFor func(width int) []column
	columns    []column

	rows         []row
	emptyMessage string

	cursor  int
	offset  int
	width   int
	visible int
}

func newTable(columnsFor func(int) []column, emptyMessage string) dataTable {
	return dataTable{
		columnsFor:   columnsFor,
		emptyMessage: emptyMessage,
	}
}

// setSize sets the table width and the number of data rows that fit.
func (t *dataTable) setSize(width, visibleRows int) {
	t.width = maxInt(cursorGutterWidth+1, width)
	t.visible = maxInt(1, visibleRows)
	t.columns = t.columnsFor(t.width - cursorGutterWidth)
	t.clampCursor()
}

// setRows replaces the data, keeping the cursor on a valid row.
func (t *dataTable) setRows(rows []row) {
	t.rows = rows
	t.clampCursor()
}

func (t *dataTable) moveUp(n int) {
	t.cursor -= n
	t.clampCursor()
}

func (t *dataTable) moveDown(n int) {
	t.cursor += n
	t.clampCursor()
}

func (t *dataTable) gotoTop() {
	t.cursor = 0
	t.clampCursor()
}

func (t *dataTable) gotoBottom() {
	t.cursor = len(t.rows) - 1
	t.clampCursor()
}

// clampCursor keeps the cursor inside the data and scrolls the window so the
// cursor stays visible.
func (t *dataTable) clampCursor() {
	if len(t.rows) == 0 {
		t.cursor = 0
		t.offset = 0

		return
	}

	t.cursor = clampInt(t.cursor, 0, len(t.rows)-1)

	visible := maxInt(1, t.visible)

	maxOffset := maxInt(0, len(t.rows)-visible)
	t.offset = clampInt(t.offset, 0, maxOffset)

	switch {
	case t.cursor < t.offset:
		t.offset = t.cursor
	case t.cursor >= t.offset+visible:
		t.offset = t.cursor - visible + 1
	}
}

// handleKey consumes navigation keys. It reports whether the key was used.
func (t *dataTable) handleKey(msg tea.KeyPressMsg) bool {
	switch msg.String() {
	case "up", "k":
		t.moveUp(1)
	case "down", "j":
		t.moveDown(1)
	case "pgup", "ctrl+u":
		t.moveUp(maxInt(1, t.visible/2))
	case "pgdown", "ctrl+d":
		t.moveDown(maxInt(1, t.visible/2))
	case "home", "g":
		t.gotoTop()
	case "end", "G":
		t.gotoBottom()
	default:
		return false
	}

	return true
}

// positionHint is the "row/total" counter shown in the pane border.
func (t dataTable) positionHint() string {
	if len(t.rows) == 0 {
		return ""
	}

	return fmt.Sprintf("%d/%d", t.cursor+1, len(t.rows))
}

// view renders the header, its rule and exactly t.visible data lines.
func (t dataTable) view(focused bool) string {
	lines := make([]string, 0, t.visible+2)
	lines = append(lines, t.headerLine(focused), t.ruleLine())

	if len(t.rows) == 0 {
		lines = append(lines, t.messageLine())

		for len(lines) < t.visible+2 {
			lines = append(lines, "")
		}

		return strings.Join(lines, "\n")
	}

	end := minInt(t.offset+t.visible, len(t.rows))

	for i := t.offset; i < end; i++ {
		lines = append(lines, t.rowLine(t.rows[i], i == t.cursor, focused))
	}

	for len(lines) < t.visible+2 {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func (t dataTable) headerLine(focused bool) string {
	style := columnHeaderStyle
	if focused {
		style = columnHeaderFocusStyle
	}

	var b strings.Builder

	b.WriteString(strings.Repeat(" ", cursorGutterWidth))

	for i, col := range t.columns {
		if i > 0 {
			b.WriteString(strings.Repeat(" ", columnGap))
		}

		b.WriteString(style.Render(fitCell(col.title, col.width, col.align)))
	}

	return b.String()
}

func (t dataTable) ruleLine() string {
	return borderStyle.Render(strings.Repeat("─", maxInt(1, t.width)))
}

func (t dataTable) messageLine() string {
	return strings.Repeat(" ", cursorGutterWidth) +
		emptyStyle.Render(ansi.Truncate(t.emptyMessage, maxInt(1, t.width-cursorGutterWidth), "…"))
}

// rowLine renders one data row. Every segment — gutter, cells, gaps and the
// trailing filler — is styled individually so the selected background covers
// the full width without swallowing the semantic foreground colors.
func (t dataTable) rowLine(r row, selected, focused bool) string {
	fill := cellStyle(toneDefault, selected, focused)

	var b strings.Builder

	marker := strings.Repeat(" ", cursorGutterWidth)
	if selected {
		marker = cursorMarker + strings.Repeat(" ", cursorGutterWidth-1)
	}

	b.WriteString(cursorBarStyle(selected, focused).Render(marker))

	used := cursorGutterWidth

	for i, col := range t.columns {
		if i > 0 {
			b.WriteString(fill.Render(strings.Repeat(" ", columnGap)))
			used += columnGap
		}

		value := cell{}
		if i < len(r) {
			value = r[i]
		}

		b.WriteString(
			cellStyle(value.tone, selected, focused).
				Render(fitCell(value.text, col.width, col.align)),
		)

		used += col.width
	}

	if rest := t.width - used; rest > 0 {
		b.WriteString(fill.Render(strings.Repeat(" ", rest)))
	}

	return b.String()
}

// fitCell truncates or pads a value to exactly width display cells.
func fitCell(value string, width int, align alignment) string {
	if width <= 0 {
		return ""
	}

	value = ansi.Truncate(value, width, "…")

	pad := width - ansi.StringWidth(value)
	if pad <= 0 {
		return value
	}

	if align == alignRight {
		return strings.Repeat(" ", pad) + value
	}

	return value + strings.Repeat(" ", pad)
}

// renderRows converts a slice of items into table rows.
func renderRows[T any](items []T, toRow func(T) row) []row {
	rows := make([]row, 0, len(items))

	for _, item := range items {
		rows = append(rows, toRow(item))
	}

	return rows
}
