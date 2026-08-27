package collect

import (
	"fmt"
	"strings"

	"github.com/volknichtx/argus/model"
)

const establishedState = "ESTAB"

// ConnectionCollector collects currently established TCP and UDP connections.
//
// We intentionally collect using a stable ss column layout and filter ESTAB
// rows in Go. This keeps parseConnections independent from output-layout
// changes caused by ss state-filter syntax.
//
// Expected ss row:
//
//	tcp ESTAB 0 0 10.0.0.10:22 10.0.0.20:63112 users:(("sshd",pid=4711,fd=4))
func ConnectionCollector() ([]model.Connection, error) {
	output, err := execCommand(
		"ss",
		"-H",
		"-tunp",
	).Output()
	if err != nil {
		return nil, fmt.Errorf(
			"execute ss for connections: %w",
			err,
		)
	}

	return parseConnections(parseRow(output)), nil
}

// parseConnections converts ss rows into Connection models.
//
// Like parsePorts it skips a row it cannot read rather than failing the batch,
// so one unparseable peer address does not cost the pane every other connection.
func parseConnections(
	rawRows []string,
) []model.Connection {
	var connections []model.Connection

	for _, row := range rawRows {
		fields := strings.Fields(row)

		// Expected:
		//
		// NETID STATE RECV-Q SEND-Q LOCAL PEER [PROCESS]
		if len(fields) < 6 {
			continue
		}

		// Ignore listeners and unconnected UDP sockets.
		if fields[1] != establishedState {
			continue
		}

		localAddr, localPort, err := parseAddress(fields[4])
		if err != nil {
			debugLog.Printf("skip connection %q: %v", row, err)
			continue
		}

		remoteAddr, remotePort, err := parseAddress(fields[5])
		if err != nil {
			debugLog.Printf("skip connection %q: %v", row, err)
			continue
		}

		connection := model.Connection{
			Protocol:   fields[0],
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			PID:        -1,
			Process:    "undefined",
			State:      fields[1],
		}

		if len(fields) >= 7 {
			processData := strings.Join(fields[6:], " ")

			processName, pid, err := parseProcessName(processData)
			if err != nil {
				debugLog.Printf("skip process data %q: %v", processData, err)
			} else {
				connection.Process = processName
				connection.PID = pid
			}
		}

		connections = append(connections, connection)
	}

	return connections
}
