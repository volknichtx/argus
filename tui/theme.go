package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// tone is the semantic meaning of a cell, resolved to a concrete color at
// render time. Rows never carry pre-rendered ANSI, so the cursor highlight can
// always own the background of the whole line.
type tone int

const (
	toneDefault tone = iota
	toneMuted
	toneAccent
	toneWarn
	toneDanger
	toneOK
)

// String keeps test failures and debug output readable; a bare tone would
// otherwise print as an integer.
func (t tone) String() string {
	switch t {
	case toneMuted:
		return "toneMuted"
	case toneAccent:
		return "toneAccent"
	case toneWarn:
		return "toneWarn"
	case toneDanger:
		return "toneDanger"
	case toneOK:
		return "toneOK"
	default:
		return "toneDefault"
	}
}

// A restrained palette: chrome stays out of the way, color only carries meaning.
var (
	colText        = lipgloss.Color("#c6c6c6")
	colTextStrong  = lipgloss.Color("#eeeeee")
	colTextMuted   = lipgloss.Color("#8a8a8a")
	colTextFaint   = lipgloss.Color("#5f5f5f")
	colAccent      = lipgloss.Color("#5fafaf")
	colBorder      = lipgloss.Color("#3a3a3a")
	colBorderFocus = lipgloss.Color("#5fafaf")
	colWarn        = lipgloss.Color("#d7af5f")
	colDanger      = lipgloss.Color("#d78787")
	colOK          = lipgloss.Color("#87af87")

	colCursorBg      = lipgloss.Color("#00627a")
	colCursorBgBlur  = lipgloss.Color("#303030")
	colCursorBarOn   = colAccent
	colCursorBarBlur = lipgloss.Color("#585858")
)

var (
	appNameStyle = lipgloss.NewStyle().
			Foreground(colAccent).
			Bold(true)

	headerMetaStyle = lipgloss.NewStyle().
			Foreground(colTextFaint)

	headerCountStyle = lipgloss.NewStyle().
				Foreground(colTextMuted)

	borderStyle = lipgloss.NewStyle().
			Foreground(colBorder)

	borderFocusStyle = lipgloss.NewStyle().
				Foreground(colBorderFocus)

	paneTitleStyle = lipgloss.NewStyle().
			Foreground(colTextMuted)

	paneTitleFocusStyle = lipgloss.NewStyle().
				Foreground(colAccent).
				Bold(true)

	paneKeyStyle = lipgloss.NewStyle().
			Foreground(colTextFaint)

	paneKeyFocusStyle = lipgloss.NewStyle().
				Foreground(colAccent)

	columnHeaderStyle = lipgloss.NewStyle().
				Foreground(colTextFaint)

	columnHeaderFocusStyle = lipgloss.NewStyle().
				Foreground(colTextMuted)

	emptyStyle = lipgloss.NewStyle().
			Foreground(colTextFaint).
			Italic(true)

	statusKeyStyle = lipgloss.NewStyle().
			Foreground(colTextMuted)

	statusLabelStyle = lipgloss.NewStyle().
				Foreground(colTextFaint)

	statusActiveStyle = lipgloss.NewStyle().
				Foreground(colAccent).
				Bold(true)

	statusSepStyle = lipgloss.NewStyle().
			Foreground(colBorder)

	errorStyle = lipgloss.NewStyle().
			Foreground(colDanger).
			Bold(true)
)

// toneForeground maps a tone to its foreground color.
func toneForeground(t tone) color.Color {
	switch t {
	case toneMuted:
		return colTextMuted
	case toneAccent:
		return colAccent
	case toneWarn:
		return colWarn
	case toneDanger:
		return colDanger
	case toneOK:
		return colOK
	default:
		return colText
	}
}

// cellStyle builds the style for a single cell. The cursor background is baked
// into every cell of the selected row instead of being layered on top of an
// already rendered line, which is what keeps the highlight unbroken across
// colored cells.
func cellStyle(t tone, selected, focused bool) lipgloss.Style {
	style := lipgloss.NewStyle()

	if !selected {
		return style.Foreground(toneForeground(t))
	}

	if !focused {
		return style.
			Foreground(colText).
			Background(colCursorBgBlur)
	}

	fg := toneForeground(t)
	if t == toneDefault {
		fg = colTextStrong
	}

	return style.
		Foreground(fg).
		Background(colCursorBg)
}

// cursorBarStyle renders the thin marker in front of the selected row.
func cursorBarStyle(selected, focused bool) lipgloss.Style {
	style := lipgloss.NewStyle()

	switch {
	case selected && focused:
		return style.Foreground(colCursorBarOn).Background(colCursorBg)
	case selected:
		return style.Foreground(colCursorBarBlur).Background(colCursorBgBlur)
	default:
		return style.Foreground(colTextFaint)
	}
}
