package tui

import "strconv"

func maxInt(a, b int) int {
	if a > b {
		return a
	}

	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func clampInt(value, low, high int) int {
	return minInt(maxInt(value, low), high)
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

func formatSize(width, height int) string {
	return itoa(width) + "×" + itoa(height)
}
