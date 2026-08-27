package tui

import (
	"github.com/volknichtx/argus/internal/netutil"
	models "github.com/volknichtx/argus/model"
)

// authRows renders the auth pane newest first.
//
// The events arrive oldest first, because that is the order journald hands them
// over and the order the retention cap trims from. Rendering them that way put
// the newest event below the fold on any pane that was full, which is exactly
// the one a live monitor exists to show.
func authRows(events []models.AuthEventLog) []row {
	rows := make([]row, 0, len(events))

	for i := len(events) - 1; i >= 0; i-- {
		rows = append(rows, authToRow(events[i]))
	}

	return rows
}

func authToRow(event models.AuthEventLog) row {
	status := toned("FAILED", toneDanger)
	if event.Success {
		status = toned("OK", toneOK)
	}

	// Only an origin off this machine is worth a second look. Loopback is this
	// machine talking to itself, and the engine refuses to grade it above
	// normal — painting it amber here would have the panes disagree about the
	// same event.
	source := dim("local")

	if event.SourceIP != nil {
		address := event.SourceIP.String()

		if event.SourcePort > 0 {
			address += ":" + itoa(event.SourcePort)
		}

		source = dim(address)
		if netutil.IsRemoteHost(event.SourceIP.String()) {
			source = toned(address, toneWarn)
		}
	}

	return row{
		dim(event.Timestamp.Format("2006-01-02 15:04:05")),
		status,
		dim(event.Service),
		toned(string(event.EventType), toneForEventType(event.EventType)),
		valueOrUnknown(event.User),
		source,
	}
}
