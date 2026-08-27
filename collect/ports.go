package collect

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/volknichtx/argus/model"
)

var processRegex = regexp.MustCompile(`"([^"]+)",pid=(\d+)`)

// PortCollector collects currently listening TCP and UDP sockets.
//
// Command:
//
//	ss -H -lntup
//
// Flags:
//
//	-H  do not print the header
//	-l  display only listening sockets
//	-n  do not resolve service names
//	-t  display TCP sockets
//	-u  display UDP sockets
//	-p  show process information
func PortCollector() ([]model.Port, error) {
	output, err := execCommand(
		"ss",
		"-H",
		"-lntup",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("execute ss: %w", err)
	}

	return parsePorts(parseRow(output)), nil
}

// parseRow splits raw command output into individual rows.
func parseRow(data []byte) []string {
	output := strings.TrimSpace(string(data))
	if output == "" {
		return nil
	}

	return strings.Split(output, "\n")
}

// parsePorts converts ss rows into Port models.
//
// Expected ss layout:
//
//	NETID STATE RECV-Q SEND-Q LOCAL-ADDRESS:PORT PEER-ADDRESS:PORT [PROCESS]
//
// The peer column is intentionally ignored for listening sockets because
// a listener does not have a concrete remote peer.
//
// A row that does not parse is skipped, not turned into an error for the whole
// batch. One unexpected line — a future ss release, an address family we do not
// know — would otherwise blank the entire pane, and losing every listener to
// save one is the wrong trade for a monitor.
func parsePorts(rawRows []string) []model.Port {
	var ports []model.Port

	for _, row := range rawRows {
		fields := strings.Fields(row)

		if len(fields) < 6 {
			continue
		}

		addr, localPort, err := parseAddress(fields[4])
		if err != nil {
			debugLog.Printf("skip listening socket %q: %v", row, err)
			continue
		}

		port := model.Port{
			Protocol: fields[0],
			Addr:     addr,
			Port:     localPort,
			PID:      -1,
			Process:  "undefined",
			State:    fields[1],
		}

		if len(fields) >= 7 {
			processData := strings.Join(fields[6:], " ")

			// Unreadable process data costs the row its PID and name, not the
			// row itself: the socket is listening either way, and that is the
			// part that matters.
			processName, pid, err := parseProcessName(processData)
			if err != nil {
				debugLog.Printf("skip process data %q: %v", processData, err)
			} else {
				port.Process = processName
				port.PID = pid
			}
		}

		ports = append(ports, port)
	}

	return ports
}

// parseAddress splits an ss address into address and port.
//
// ss may output IPv6 link-local addresses like:
//
//	[fe80::1234:5678]%eno1:546
//
// net.SplitHostPort expects:
//
//	[fe80::1234:5678%eno1]:546
func parseAddress(data string) (addr, port string, err error) {
	if strings.HasPrefix(data, "[") {
		closingBracket := strings.Index(data, "]")

		if closingBracket != -1 &&
			closingBracket+1 < len(data) &&
			data[closingBracket+1] == '%' {

			lastColon := strings.LastIndex(data, ":")
			if lastColon == -1 || lastColon <= closingBracket {
				return "", "", fmt.Errorf(
					"invalid IPv6 address %q",
					data,
				)
			}

			ip := data[1:closingBracket]
			zone := data[closingBracket+1 : lastColon]
			port := data[lastColon+1:]

			return ip + zone, port, nil
		}
	}

	addr, port, err = net.SplitHostPort(data)
	if err != nil {
		return "", "", fmt.Errorf(
			"split host and port %q: %w",
			data,
			err,
		)
	}

	return addr, port, nil
}

// parseProcessName extracts the process name and PID from the process data
// appended by `ss -p`.
//
// Example:
//
//	users:(("sshd",pid=4711,fd=3))
func parseProcessName(
	processData string,
) (processName string, pid int, err error) {
	processName = "undefined"
	pid = -1

	match := processRegex.FindStringSubmatch(processData)
	if len(match) != 3 {
		return processName, pid, nil
	}

	processName = match[1]

	pid, err = strconv.Atoi(match[2])
	if err != nil {
		return "undefined", -1, fmt.Errorf(
			"parse pid %q: %w",
			match[2],
			err,
		)
	}

	return processName, pid, nil
}
