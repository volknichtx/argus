package tui

import "math"

// Space between two columns. Columns themselves carry no padding, so the gap is
// the only separator and every table lines up on the same grid.
const columnGap = 2

type alignment int

const (
	alignLeft alignment = iota
	alignRight
)

type column struct {
	title string
	width int
	align alignment
}

// columnSpec describes how a column behaves when the pane is resized: it never
// drops below min, grows by weight, and stops at max so a wide terminal does
// not stretch a four-character value across half the screen.
type columnSpec struct {
	title  string
	min    int
	max    int
	weight int
	align  alignment
}

func portColumns(width int) []column {
	return buildColumns(width, []columnSpec{
		{title: "PROTO", min: 5},
		{title: "ADDRESS", min: 14, max: 46, weight: 5},
		{title: "PORT", min: 5, align: alignRight},
		{title: "STATE", min: 6},
		{title: "PID", min: 6, max: 8, weight: 1, align: alignRight},
		{title: "PROCESS", min: 8, max: 22, weight: 2},
	})
}

func connectionColumns(width int) []column {
	return buildColumns(width, []columnSpec{
		{title: "PROTO", min: 5},
		{title: "DIR", min: 3},
		{title: "LOCAL", min: 14, max: 46, weight: 5},
		{title: "REMOTE", min: 14, max: 46, weight: 5},
		{title: "STATE", min: 6},
		{title: "PID", min: 6, max: 8, weight: 1, align: alignRight},
		{title: "PROCESS", min: 8, max: 22, weight: 2},
	})
}

// hostColumns is the correlation pane: the address gets the room, every signal
// is a narrow count so the whole join fits one line.
func hostColumns(width int) []column {
	return buildColumns(width, []columnSpec{
		{title: "HOST", min: 15, max: 46, weight: 4},
		{title: "CONCERN", min: 8},
		{title: "INBOUND", min: 8, max: 20, weight: 2},
		{title: "OUTBOUND", min: 8, align: alignRight},
		{title: "SESSIONS", min: 8, align: alignRight},
		{title: "LOGINS", min: 6, align: alignRight},
		{title: "FAILED", min: 6, align: alignRight},
		{title: "ROOT", min: 4, align: alignRight},
		{title: "USERS", min: 10, max: 28, weight: 3},
	})
}

func sessionColumns(width int) []column {
	return buildColumns(width, []columnSpec{
		{title: "USER", min: 10, max: 22, weight: 2},
		{title: "TTY", min: 7, max: 12, weight: 1},
		{title: "LOGIN", min: 16, max: 20, weight: 1},
		{title: "IDLE", min: 6, max: 10, weight: 1, align: alignRight},
		{title: "PID", min: 5, max: 8, weight: 1, align: alignRight},
		{title: "SOURCE", min: 10, max: 46, weight: 3},
	})
}

func authColumns(width int) []column {
	return buildColumns(width, []columnSpec{
		{title: "TIME", min: 19},
		{title: "STATUS", min: 7},
		{title: "SERVICE", min: 8, max: 14, weight: 1},
		{title: "EVENT", min: 13, max: 20, weight: 2},
		{title: "USER", min: 10, max: 22, weight: 2},
		{title: "SOURCE", min: 14, max: 46, weight: 3},
	})
}

// buildColumns distributes totalWidth (gaps included) over the given specs:
// every column gets its minimum first, then the leftover is handed out by
// weight. When there is not even room for the minimums, all columns shrink
// proportionally so the table still fits instead of overflowing the pane.
func buildColumns(totalWidth int, specs []columnSpec) []column {
	if len(specs) == 0 {
		return nil
	}

	// Below one cell per column plus the gaps between them not even a shrunk
	// table fits, so the trailing columns are dropped instead. Overflowing here
	// would push the pane border off screen; a table showing its first columns
	// only is still readable.
	specs = specs[:fittingColumns(totalWidth, len(specs))]

	contentWidth := totalWidth - (len(specs)-1)*columnGap
	contentWidth = maxInt(len(specs), contentWidth)

	widths := make([]int, len(specs))

	minTotal := 0
	totalWeight := 0

	for i, spec := range specs {
		widths[i] = maxInt(1, spec.min)
		minTotal += widths[i]
		totalWeight += spec.weight
	}

	if contentWidth < minTotal {
		used := 0

		for i, spec := range specs {
			widths[i] = maxInt(1, spec.min*contentWidth/minTotal)
			used += widths[i]
		}

		adjustWidths(widths, contentWidth-used)
	} else if totalWeight > 0 {
		grow(widths, specs, contentWidth-minTotal)
	}

	// Width past every column's maximum is deliberately left unused: a short
	// table that ends mid-pane reads better than one with cavernous columns.

	columns := make([]column, len(specs))

	for i, spec := range specs {
		columns[i] = column{
			title: spec.title,
			width: widths[i],
			align: spec.align,
		}
	}

	return columns
}

// fittingColumns is how many of n columns fit in totalWidth at one cell each
// with a gap between every pair, never fewer than one: a table with no columns
// at all would render as a blank box.
func fittingColumns(totalWidth, n int) int {
	for count := n; count > 1; count-- {
		if count+(count-1)*columnGap <= totalWidth {
			return count
		}
	}

	return 1
}

// grow hands out spare width in weighted rounds, skipping columns that have
// reached their maximum. The final round falls back to one cell per column so
// the leftovers do not all land on whichever column comes first.
func grow(widths []int, specs []columnSpec, spare int) {
	for spare > 0 {
		eligible := 0

		for i, spec := range specs {
			if roomFor(spec, widths[i]) > 0 {
				eligible += spec.weight
			}
		}

		if eligible == 0 {
			return
		}

		for i, spec := range specs {
			room := minInt(roomFor(spec, widths[i]), spare)
			if room <= 0 {
				continue
			}

			step := spec.weight
			if spare < eligible {
				step = 1
			}

			grant := minInt(step, room)
			widths[i] += grant
			spare -= grant

			if spare == 0 {
				return
			}
		}
	}
}

// roomFor is how much a column may still grow; zero-weight columns never do.
func roomFor(spec columnSpec, width int) int {
	if spec.weight <= 0 {
		return 0
	}

	if spec.max <= 0 {
		return math.MaxInt
	}

	return maxInt(0, spec.max-width)
}

// adjustWidths spreads a leftover delta (positive or negative) across widths
// without letting any column drop below one cell.
func adjustWidths(widths []int, delta int) {
	if len(widths) == 0 || delta == 0 {
		return
	}

	if delta > 0 {
		for i := 0; delta > 0; i = (i + 1) % len(widths) {
			widths[i]++
			delta--
		}

		return
	}

	for delta < 0 {
		shrunk := false

		for i := len(widths) - 1; i >= 0 && delta < 0; i-- {
			if widths[i] <= 1 {
				continue
			}

			widths[i]--
			delta++
			shrunk = true
		}

		if !shrunk {
			return
		}
	}
}
