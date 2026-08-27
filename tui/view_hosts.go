package tui

import (
	"strings"

	"github.com/volknichtx/argus/correlation"
)

// concernLabels are the on-screen names of the concern levels, upper case so a
// critical host is legible at a glance.
var concernLabels = map[correlation.Concern]string{
	correlation.ConcernCritical: "CRITICAL",
	correlation.ConcernElevated: "ELEVATED",
	correlation.ConcernNormal:   "normal",
}

// toneForConcern maps a concern level onto the shared tone system, so an
// alarming host lights up with the same semantics as a failed login or an
// exposed port.
func toneForConcern(concern correlation.Concern) tone {
	switch concern {
	case correlation.ConcernCritical:
		return toneDanger
	case correlation.ConcernElevated:
		return toneWarn
	default:
		return toneMuted
	}
}

// hostToRow projects one correlated host onto a table row.
//
// Unlike the raw panes, the whole row carries the concern tone rather than just
// one meaningful cell: here the grade is a statement about the host as a whole,
// and this pane's job is to let an alarming host stand out while the ordinary
// ones recede.
func hostToRow(host correlation.CorrelatedHost) row {
	rowTone := toneForConcern(host.Concern)

	return row{
		toned(host.Address, rowTone),
		toned(concernLabels[host.Concern], rowTone),
		countCell(host.InboundCount(), rowTone, inboundDetail(host)),
		countCell(host.OutboundCount(), rowTone, ""),
		countCell(len(host.Sessions), rowTone, ""),
		countCell(host.LoginCount(), rowTone, ""),
		countCell(host.FailedAuthCount(), rowTone, ""),
		countCell(host.EscalationCount(), rowTone, ""),
		userCell(host.Users(), rowTone),
	}
}

// inboundDetail names the local ports a host reached, e.g. "→ :22".
func inboundDetail(host correlation.CorrelatedHost) string {
	ports := host.InboundPorts()
	if len(ports) == 0 {
		return ""
	}

	return "→ :" + strings.Join(ports, ",:")
}

// countCell renders a signal count, dimming it away entirely when there is
// nothing to report so the eye only lands on cells that carry something.
func countCell(count int, rowTone tone, detail string) cell {
	if count == 0 {
		return dim(unknownValue)
	}

	text := itoa(count)
	if detail != "" {
		text += " " + detail
	}

	return toned(text, rowTone)
}

func userCell(users []string, rowTone tone) cell {
	if len(users) == 0 {
		return dim(unknownValue)
	}

	return toned(strings.Join(users, ", "), rowTone)
}
