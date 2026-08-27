package tui

import "testing"

// totalWidth is what a set of columns actually occupies, gaps included.
func totalWidth(columns []column) int {
	if len(columns) == 0 {
		return 0
	}

	total := (len(columns) - 1) * columnGap

	for _, col := range columns {
		total += col.width
	}

	return total
}

// Whatever the terminal size, a table must never claim more room than the pane
// gave it — an overflowing column pushes the pane border off screen.
func TestColumnsNeverOverflowThePane(t *testing.T) {
	layouts := map[string]func(int) []column{
		"ports":       portColumns,
		"connections": connectionColumns,
		"hosts":       hostColumns,
		"sessions":    sessionColumns,
		"auth":        authColumns,
	}

	widths := []int{300, 200, 160, 120, 100, 80, 60, 40, 20, 10, 5, 1}

	for name, columnsFor := range layouts {
		for _, width := range widths {
			columns := columnsFor(width)

			if got := totalWidth(columns); got > width {
				t.Errorf("%s columns take %d cells at width %d", name, got, width)
			}

			for i, col := range columns {
				if col.width < 1 {
					t.Errorf("%s column %d has width %d at pane width %d",
						name, i, col.width, width)
				}
			}
		}
	}
}

// Below the sum of the minimums every column shrinks proportionally instead of
// the last ones being dropped, so the table stays readable rather than losing
// its right-hand half.
func TestColumnsShrinkProportionallyWhenCramped(t *testing.T) {
	specs := []columnSpec{
		{title: "A", min: 10},
		{title: "B", min: 20},
		{title: "C", min: 30},
	}

	columns := buildColumns(20, specs)

	if got := totalWidth(columns); got > 20 {
		t.Fatalf("columns take %d cells, want at most 20", got)
	}

	for i, col := range columns {
		if col.width < 1 {
			t.Fatalf("column %d collapsed to %d", i, col.width)
		}
	}

	// The widest specification must still end up the widest column.
	if columns[0].width > columns[2].width {
		t.Errorf("widths %v do not keep the specified proportions",
			[]int{columns[0].width, columns[1].width, columns[2].width})
	}
}

// Spare width goes to the columns that carry variable-length values, and stops
// at their maximum so a short value is not stretched across the pane.
func TestColumnsGrowByWeightAndStopAtMax(t *testing.T) {
	specs := []columnSpec{
		{title: "FIXED", min: 5},
		{title: "GROWS", min: 10, max: 20, weight: 3},
		{title: "GROWS SLOWLY", min: 10, max: 40, weight: 1},
	}

	columns := buildColumns(200, specs)

	if columns[0].width != 5 {
		t.Errorf("zero-weight column grew to %d, want 5", columns[0].width)
	}

	if columns[1].width != 20 {
		t.Errorf("weighted column = %d, want its maximum of 20", columns[1].width)
	}

	if columns[2].width != 40 {
		t.Errorf("weighted column = %d, want its maximum of 40", columns[2].width)
	}

	// Width past every maximum is deliberately left unused rather than padded
	// into the last column.
	if got := totalWidth(columns); got >= 200 {
		t.Errorf("columns consumed %d of 200, want the surplus left unused", got)
	}
}

// An unbounded weighted column absorbs whatever is left.
func TestUnboundedColumnTakesTheRemainder(t *testing.T) {
	columns := buildColumns(100, []columnSpec{
		{title: "FIXED", min: 10},
		{title: "REST", min: 10, weight: 1},
	})

	if got := totalWidth(columns); got != 100 {
		t.Errorf("columns take %d cells, want the full 100", got)
	}
}

func TestBuildColumnsWithoutSpecs(t *testing.T) {
	if got := buildColumns(100, nil); got != nil {
		t.Errorf("buildColumns(100, nil) = %v, want nil", got)
	}
}

// The stacked panes must give way rather than push the top row below the size
// at which it can show anything.
func TestLayoutReclaimsHeightForTheTopRow(t *testing.T) {
	// Row counts far beyond what fits, so every stacked pane wants its cap.
	counts := rowCounts{ports: 200, connections: 200, hosts: 200, sessions: 200, auth: 200}

	for _, height := range []int{minWideHeight, 40, 60, 100} {
		l := calculateLayout(160, height, counts)

		if l.mode != layoutWide {
			t.Fatalf("height %d produced the narrow layout", height)
		}

		if l.topHeight < minPaneHeight {
			t.Errorf("height %d left the top row at %d, want at least %d",
				height, l.topHeight, minPaneHeight)
		}

		total := l.topHeight + l.hostsHeight + l.sessionsHeight + l.authHeight + wideChromeRows

		if total > height {
			t.Errorf("height %d: panes claim %d rows", height, total)
		}
	}
}

// An empty dashboard still needs one usable row per pane.
func TestLayoutKeepsAMinimumWithNoData(t *testing.T) {
	l := calculateLayout(160, 48, rowCounts{})

	for name, height := range map[string]int{
		"top":      l.topHeight,
		"hosts":    l.hostsHeight,
		"sessions": l.sessionsHeight,
		"auth":     l.authHeight,
	} {
		if height < minPaneHeight {
			t.Errorf("%s pane = %d rows, want at least %d", name, height, minPaneHeight)
		}
	}
}

// Regression: the minimum-width floor counted one cell per column but not the
// gaps between them, so a table narrower than that floor overflowed its pane.
// Only the 64-column terminal guard kept it off screen.
func TestColumnsAreDroppedRatherThanOverflowing(t *testing.T) {
	specs := []columnSpec{
		{title: "A", min: 5},
		{title: "B", min: 5},
		{title: "C", min: 5},
		{title: "D", min: 5},
	}

	for width := 1; width <= 20; width++ {
		columns := buildColumns(width, specs)

		if len(columns) == 0 {
			t.Fatalf("width %d produced no columns at all", width)
		}

		if got := totalWidth(columns); got > width {
			t.Errorf("width %d: columns take %d cells", width, got)
		}
	}
}

func TestFittingColumns(t *testing.T) {
	tests := []struct {
		name       string
		totalWidth int
		columns    int
		want       int
	}{
		{name: "everything fits", totalWidth: 100, columns: 4, want: 4},
		{name: "exactly enough for four", totalWidth: 4 + 3*columnGap, columns: 4, want: 4},
		{name: "one cell short of four", totalWidth: 4 + 3*columnGap - 1, columns: 4, want: 3},
		{name: "room for two", totalWidth: 2 + columnGap, columns: 4, want: 2},
		{name: "never fewer than one", totalWidth: 1, columns: 4, want: 1},
		{name: "not even one full cell", totalWidth: 0, columns: 4, want: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fittingColumns(tc.totalWidth, tc.columns); got != tc.want {
				t.Errorf("fittingColumns(%d, %d) = %d, want %d",
					tc.totalWidth, tc.columns, got, tc.want)
			}
		})
	}
}
