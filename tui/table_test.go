package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// numberedTable is a table with enough rows to scroll, so the cursor and the
// visible window can be told apart.
func numberedTable(t *testing.T, rows, visible int) dataTable {
	t.Helper()

	table := newTable(portColumns, "nothing here")

	data := make([]row, rows)
	for i := range data {
		data[i] = row{txt("row"), txt(itoa(i))}
	}

	table.setRows(data)
	table.setSize(80, visible)

	return table
}

// Every key the README lists has to move the cursor the way it says.
func TestTableNavigationKeys(t *testing.T) {
	tests := []struct {
		name       string
		keys       []tea.KeyPressMsg
		wantCursor int
	}{
		{
			name:       "j moves down",
			keys:       []tea.KeyPressMsg{{Code: 'j', Text: "j"}},
			wantCursor: 1,
		},
		{
			name:       "k moves back up",
			keys:       []tea.KeyPressMsg{{Code: 'j', Text: "j"}, {Code: 'j', Text: "j"}, {Code: 'k', Text: "k"}},
			wantCursor: 1,
		},
		{
			name:       "arrow keys do the same",
			keys:       []tea.KeyPressMsg{{Code: tea.KeyDown}, {Code: tea.KeyDown}, {Code: tea.KeyUp}},
			wantCursor: 1,
		},
		{
			name:       "G jumps to the last row",
			keys:       []tea.KeyPressMsg{{Code: 'G', Text: "G", Mod: tea.ModShift}},
			wantCursor: 19,
		},
		{
			name: "g returns to the first",
			keys: []tea.KeyPressMsg{
				{Code: 'G', Text: "G", Mod: tea.ModShift},
				{Code: 'g', Text: "g"},
			},
			wantCursor: 0,
		},
		{
			name:       "end jumps to the last row",
			keys:       []tea.KeyPressMsg{{Code: tea.KeyEnd}},
			wantCursor: 19,
		},
		{
			name:       "home returns to the first",
			keys:       []tea.KeyPressMsg{{Code: tea.KeyEnd}, {Code: tea.KeyHome}},
			wantCursor: 0,
		},
		{
			name:       "pgdown moves half a screen",
			keys:       []tea.KeyPressMsg{{Code: tea.KeyPgDown}},
			wantCursor: 2,
		},
		{
			name:       "pgup moves back",
			keys:       []tea.KeyPressMsg{{Code: tea.KeyEnd}, {Code: tea.KeyPgUp}},
			wantCursor: 17,
		},
		{
			name:       "ctrl+d and ctrl+u are the same jump",
			keys:       []tea.KeyPressMsg{{Code: 'd', Mod: tea.ModCtrl}, {Code: 'd', Mod: tea.ModCtrl}, {Code: 'u', Mod: tea.ModCtrl}},
			wantCursor: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table := numberedTable(t, 20, 5)

			for _, key := range tc.keys {
				if !table.handleKey(key) {
					t.Fatalf("key %v was not consumed", key)
				}
			}

			if table.cursor != tc.wantCursor {
				t.Errorf("cursor = %d, want %d", table.cursor, tc.wantCursor)
			}
		})
	}
}

// A key the table does not use has to be reported as unhandled, so the app can
// offer it to something else.
func TestTableIgnoresUnrelatedKeys(t *testing.T) {
	table := numberedTable(t, 20, 5)

	if table.handleKey(tea.KeyPressMsg{Code: 'z', Text: "z"}) {
		t.Error("an unrelated key was reported as consumed")
	}

	if table.cursor != 0 {
		t.Errorf("cursor = %d, want it untouched", table.cursor)
	}
}

// The cursor may never leave the data, however hard it is pushed.
func TestTableCursorStaysInsideTheData(t *testing.T) {
	table := numberedTable(t, 3, 5)

	table.moveUp(100)

	if table.cursor != 0 {
		t.Errorf("cursor = %d after moving up past the top, want 0", table.cursor)
	}

	table.moveDown(100)

	if table.cursor != 2 {
		t.Errorf("cursor = %d after moving down past the end, want 2", table.cursor)
	}

	// Shrinking the data must pull the cursor back with it.
	table.setRows([]row{{txt("only")}})

	if table.cursor != 0 {
		t.Errorf("cursor = %d after the data shrank, want 0", table.cursor)
	}

	// And an empty table has no cursor to place.
	table.setRows(nil)

	if table.cursor != 0 || table.offset != 0 {
		t.Errorf("cursor/offset = %d/%d on an empty table, want 0/0", table.cursor, table.offset)
	}

	if hint := table.positionHint(); hint != "" {
		t.Errorf("position hint = %q on an empty table, want none", hint)
	}
}

// Scrolling has to follow the cursor in both directions.
func TestTableWindowFollowsTheCursor(t *testing.T) {
	table := numberedTable(t, 20, 5)

	table.gotoBottom()

	if table.offset != 15 {
		t.Errorf("offset = %d at the last row, want 15", table.offset)
	}

	table.gotoTop()

	if table.offset != 0 {
		t.Errorf("offset = %d at the first row, want 0", table.offset)
	}

	// The window may never show fewer rows than it has room for while there is
	// data left to show.
	table.moveDown(7)

	if table.cursor < table.offset || table.cursor >= table.offset+table.visible {
		t.Errorf("cursor %d is outside the window [%d, %d)",
			table.cursor, table.offset, table.offset+table.visible)
	}
}

// The rendered table always occupies exactly the height it was given, empty or
// not, so the panes around it do not shift as data arrives.
func TestTableRendersExactlyItsHeight(t *testing.T) {
	t.Run("with data", func(t *testing.T) {
		table := numberedTable(t, 20, 5)

		if got, want := len(strings.Split(table.view(true), "\n")), 5+paneHeaderRows; got != want {
			t.Errorf("rendered %d lines, want %d", got, want)
		}
	})

	t.Run("empty", func(t *testing.T) {
		table := newTable(portColumns, "no listening ports")
		table.setSize(80, 5)

		out := table.view(false)

		if got, want := len(strings.Split(out, "\n")), 5+paneHeaderRows; got != want {
			t.Errorf("rendered %d lines, want %d", got, want)
		}

		if !strings.Contains(out, "no listening ports") {
			t.Error("the empty message is missing")
		}
	})
}

func TestFitCell(t *testing.T) {
	tests := []struct {
		name  string
		value string
		width int
		align alignment
		want  string
	}{
		{name: "padded left", value: "ssh", width: 6, align: alignLeft, want: "ssh   "},
		{name: "padded right", value: "22", width: 5, align: alignRight, want: "   22"},
		{name: "exact fit", value: "sshd", width: 4, align: alignLeft, want: "sshd"},
		{name: "truncated with an ellipsis", value: "verylongprocess", width: 6, align: alignLeft, want: "veryl…"},
		{name: "zero width", value: "anything", width: 0, align: alignLeft, want: ""},
		{name: "negative width", value: "anything", width: -3, align: alignLeft, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fitCell(tc.value, tc.width, tc.align)

			if got != tc.want {
				t.Errorf("fitCell(%q, %d) = %q, want %q", tc.value, tc.width, got, tc.want)
			}

			if tc.width > 0 && ansi.StringWidth(got) != tc.width {
				t.Errorf("fitCell(%q, %d) is %d cells wide, want exactly %d",
					tc.value, tc.width, ansi.StringWidth(got), tc.width)
			}
		})
	}
}

// A terminal too small for anything useful says so instead of rendering a
// mangled dashboard.
func TestTooSmallTerminalExplainsItself(t *testing.T) {
	m := sizedFixture(40, 10)

	out := m.render()

	if !strings.Contains(out, "terminal too small") {
		t.Fatalf("render() = %q, want the too-small notice", ansi.Strip(out))
	}

	// It has to name both what is required and what is available, or the user
	// cannot tell how much to resize.
	stripped := ansi.Strip(out)

	for _, want := range []string{formatSize(minTerminalWidth, minTerminalHeight), formatSize(40, 10)} {
		if !strings.Contains(stripped, want) {
			t.Errorf("notice %q does not mention %q", stripped, want)
		}
	}
}

// Before the first WindowSizeMsg there is no terminal to draw into.
func TestRenderBeforeTheFirstSizeMessage(t *testing.T) {
	m := fixtureModel()

	if got := m.render(); got != "" {
		t.Errorf("render() = %q with no size yet, want nothing", got)
	}
}

func TestFormatSize(t *testing.T) {
	if got, want := formatSize(112, 27), "112×27"; got != want {
		t.Errorf("formatSize() = %q, want %q", got, want)
	}
}
