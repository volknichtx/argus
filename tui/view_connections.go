package tui

import (
	"net"

	"github.com/volknichtx/argus/correlation"
	models "github.com/volknichtx/argus/model"
)

// directionLabels name the inferred direction. It is shown because it is what
// the row's color is graded on: without it, an amber inbound row next to a plain
// outbound one to the same kind of peer looks arbitrary.
var directionLabels = map[correlation.Direction]string{
	correlation.DirectionInbound:  "in",
	correlation.DirectionOutbound: "out",
}

// connectionRows renders the connection pane. It takes the listening ports
// because direction — and therefore the grading — is a cross-pane fact: what
// counts as inbound depends on what this machine listens on.
func connectionRows(connections []models.Connection, ports []models.Port) []row {
	listeners := correlation.ListeningPorts(ports)

	rows := make([]row, 0, len(connections))

	for _, conn := range connections {
		rows = append(rows, connToRow(conn, correlation.DirectionFor(conn, listeners)))
	}

	return rows
}

func connToRow(conn models.Connection, direction correlation.Direction) row {
	pid := dim(unknownValue)
	if conn.PID >= 0 {
		pid = dim(itoa(conn.PID))
	}

	local := net.JoinHostPort(conn.LocalAddr, conn.LocalPort)
	remote := net.JoinHostPort(conn.RemoteAddr, conn.RemotePort)

	connTone := toneForConnection(conn, direction)

	// Inbound rows carry the tone on the direction and the local endpoint too:
	// the point of an inbound row is which of our own ports was reached.
	localCell := dim(local)
	directionCell := dim(directionLabels[direction])

	if direction == correlation.DirectionInbound {
		localCell = toned(local, connTone)
		directionCell = toned(directionLabels[direction], connTone)
	}

	return row{
		dim(conn.Protocol),
		directionCell,
		localCell,
		toned(remote, connTone),
		dim(conn.State),
		pid,
		valueOrUnknown(conn.Process),
	}
}
