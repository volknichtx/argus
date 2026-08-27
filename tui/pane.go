package tui

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	// Border on both sides plus one cell of breathing room inside it.
	paneHorizontalFrame = 4
	// Top and bottom border.
	paneVerticalFrame = 2
	// Column header plus its rule.
	paneHeaderRows = 2
)

// paneChrome is everything a pane spends on decoration rather than data.
const paneChrome = paneVerticalFrame + paneHeaderRows

var paneBorder = lipgloss.RoundedBorder()

// renderPane draws a bordered box with the title woven into the top border and
// an optional hint (the row counter) flush right, k9s style. Width and height
// are the outer dimensions, so a pane never exceeds the space the layout gave it.
func renderPane(title, hint, body string, width, height int, focused bool) string {
	width = maxInt(paneHorizontalFrame, width)
	height = maxInt(paneVerticalFrame+1, height)

	chrome := borderStyle
	titleStyle := paneTitleStyle
	hintStyle := paneKeyStyle

	if focused {
		chrome = borderFocusStyle
		titleStyle = paneTitleFocusStyle
		hintStyle = paneKeyFocusStyle
	}

	inner := width - 2

	lines := make([]string, 0, height)
	lines = append(lines, topBorder(title, hint, inner, chrome, titleStyle, hintStyle))

	side := chrome.Render(paneBorder.Left)
	bodyWidth := inner - 2

	bodyLines := strings.Split(body, "\n")

	for i := 0; i < height-paneVerticalFrame; i++ {
		line := ""
		if i < len(bodyLines) {
			line = bodyLines[i]
		}

		lines = append(lines, side+" "+padToWidth(line, bodyWidth)+" "+side)
	}

	lines = append(
		lines,
		chrome.Render(paneBorder.BottomLeft+strings.Repeat(paneBorder.Bottom, inner)+paneBorder.BottomRight),
	)

	return strings.Join(lines, "\n")
}

func topBorder(
	title, hint string,
	inner int,
	chrome, titleStyle, hintStyle lipgloss.Style,
) string {
	dash := paneBorder.Top

	left := ""
	if title != "" {
		left = " " + title + " "
	}

	right := ""
	if hint != "" {
		right = " " + hint + " "
	}

	// Give up the counter before the title, and shorten the title only when the
	// pane is too narrow for even that.
	if 1+ansi.StringWidth(left)+ansi.StringWidth(right)+1 > inner {
		right = ""
	}

	if room := inner - 2; ansi.StringWidth(left) > room {
		left = ansi.Truncate(left, maxInt(0, room), "…")
	}

	fill := inner - 1 - ansi.StringWidth(left) - ansi.StringWidth(right) - 1
	fill = maxInt(0, fill)

	var b strings.Builder

	b.WriteString(chrome.Render(paneBorder.TopLeft + dash))

	if left != "" {
		b.WriteString(titleStyle.Render(left))
	}

	b.WriteString(chrome.Render(strings.Repeat(dash, fill)))

	if right != "" {
		b.WriteString(hintStyle.Render(right))
	}

	b.WriteString(chrome.Render(dash + paneBorder.TopRight))

	return b.String()
}

// padToWidth pads or truncates a rendered line to an exact display width.
func padToWidth(line string, width int) string {
	if width <= 0 {
		return ""
	}

	if w := ansi.StringWidth(line); w < width {
		return line + strings.Repeat(" ", width-w)
	}

	return ansi.Truncate(line, width, "")
}
