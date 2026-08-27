package collect

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/volknichtx/argus/model"
)

// SessionCollector collects currently logged-in user sessions
// using the `who -u` command.
//
// who is the authority on who is logged in and from where. logind is then asked
// for the session identifiers, because that is the only handle a local
// privilege change carries: su and sudo log the session they ran in, not an
// address. Without the identifier such an event cannot be tied to the login it
// happened inside, and the correlation drops it rather than guessing.
func SessionCollector() ([]model.UserSession, error) {
	var sessions []model.UserSession

	output, err := execCommand("who", "-u").Output()
	if err != nil {
		return nil, fmt.Errorf("execute who: %w", err)
	}

	parseSessions(string(output), &sessions)
	attachSessionIDs(sessions, loginSessionsByTTY())

	return sessions, nil
}

// loginctlSession is the part of `loginctl list-sessions --json` we use.
type loginctlSession struct {
	Session string `json:"session"`
	TTY     string `json:"tty"`
}

// loginSessionsByTTY asks logind which session owns which terminal.
//
// Failure is deliberately not an error. loginctl may be absent, too old for
// --json, or refuse to answer; all that costs is the link between a privilege
// change and its origin, which the correlation already treats as optional. The
// panes that matter keep working either way.
func loginSessionsByTTY() map[string]string {
	output, err := execCommand("loginctl", "list-sessions", "--json=short", "--no-pager").Output()
	if err != nil {
		debugLog.Printf("skip logind session ids: %v", err)
		return nil
	}

	var sessions []loginctlSession

	if err := json.Unmarshal(output, &sessions); err != nil {
		debugLog.Printf("skip logind session ids: %v", err)
		return nil
	}

	byTTY := make(map[string]string, len(sessions))

	for _, session := range sessions {
		if session.TTY == "" || session.Session == "" {
			continue
		}

		// Two sessions on one terminal would make the mapping ambiguous, and an
		// ambiguous link is worse than none: it would attribute a privilege
		// change to the wrong login.
		if _, taken := byTTY[session.TTY]; taken {
			byTTY[session.TTY] = ""
			continue
		}

		byTTY[session.TTY] = session.Session
	}

	return byTTY
}

// attachSessionIDs fills in the logind identifier for the sessions who reported,
// matching on the terminal both tools name.
func attachSessionIDs(sessions []model.UserSession, byTTY map[string]string) {
	for i := range sessions {
		sessions[i].ID = byTTY[sessions[i].TTY]
	}
}

// parseSessions parses the output of `who -u`.
//
// Example:
//
// alice tty2  2026-08-15 18:32  old  1143
// alice pts/1 2026-08-15 19:05  .    5832 (::1)
func parseSessions(
	output string,
	sessions *[]model.UserSession,
) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		fields := strings.Fields(line)

		// Expected minimum:
		// USER TTY DATE TIME IDLE PID
		if len(fields) < 6 {
			continue
		}

		session := model.UserSession{
			User:      fields[0],
			TTY:       fields[1],
			LoginDate: fields[2],
			LoginTime: fields[3],
			Idle:      fields[4],
			PID:       -1,
			Source:    "local",
		}

		pid, err := strconv.Atoi(fields[5])
		if err == nil {
			session.PID = pid
		}

		// Optional source field:
		// (:0)
		// (::1)
		// (10.0.0.30)
		// (hostname)
		if len(fields) >= 7 {
			source := strings.Join(fields[6:], " ")
			source = strings.TrimPrefix(source, "(")
			source = strings.TrimSuffix(source, ")")
			source = strings.TrimSpace(source)

			if source != "" {
				session.Source = source
			}
		}

		*sessions = append(*sessions, session)
	}
}
