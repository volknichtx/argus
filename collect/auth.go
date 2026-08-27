package collect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/volknichtx/argus/model"
)

const initialJournalEntries = 50

var paths = []string{
	"/var/log/auth.log",
	"/var/log/secure",
}

var (
	sshUserFromRegex        = regexp.MustCompile(`(?i)\bfor (?:invalid user )?([^\s]+) from ([^\s]+) port ([0-9]+)\b`)
	sshInvalidUserFromRegex = regexp.MustCompile(`(?i)\binvalid user ([^\s]+) from ([^\s]+) port ([0-9]+)\b`)
	pamUserRegex            = regexp.MustCompile(`(?:^|[\s;])user=([^\s;]+)`)
	rhostRegex              = regexp.MustCompile(`(?:^|[\s;])rhost=([^\s;]+)`)
	sudoActorRegex          = regexp.MustCompile(`^([^:\s]+)\s*:`)
	loginSessionUserRegex   = regexp.MustCompile(`(?i)\bsession opened for user ([^\s(]+)`)

	// sudo's own log line names the account it ran the command as.
	sudoTargetRegex = regexp.MustCompile(`(?:^|[\s;])USER=([^\s;]+)`)
)

// authServices maps every journal identifier argus reads onto the canonical
// service name the message parsers dispatch on.
//
// It is the single source of truth for two things that must not drift apart:
// the matches handed to journalctl, and the classification done here. An
// identifier missing from this table is neither fetched nor parsed.
//
// openssh 9.8 split sshd into per-phase binaries, which is why the session and
// auth variants are listed alongside the plain name.
var authServices = map[string]string{
	"sshd":         "sshd",
	"sshd-session": "sshd",
	"sshd-auth":    "sshd",
	"sudo":         "sudo",
	"su":           "su",
	"login":        "login",
}

// journalMatches restricts journalctl to the services in authServices.
//
// Without it journalctl returns the entire system journal. The initial window
// is then filled with unrelated entries and hardly any authentication at all,
// and every poll afterwards parses the machine's complete journal delta only to
// discard almost all of it.
//
// journalctl ORs matches on the same field and ORs the groups either side of a
// "+", so this reads: SYSLOG_IDENTIFIER is one of ours, or _COMM is. That
// mirrors authEventFilter, which prefers the identifier and falls back to the
// command name.
//
// The filter is deliberately a superset of what matchAuthService accepts, which
// remains the authority on whether an entry is relevant.
func journalMatches() []string {
	identifiers := make([]string, 0, len(authServices))

	for identifier := range authServices {
		identifiers = append(identifiers, identifier)
	}

	// Sorted so the argument list is stable and can be asserted on.
	sort.Strings(identifiers)

	matches := make([]string, 0, len(identifiers)*2+1)

	for _, identifier := range identifiers {
		matches = append(matches, "SYSLOG_IDENTIFIER="+identifier)
	}

	matches = append(matches, "+")

	for _, identifier := range identifiers {
		matches = append(matches, "_COMM="+identifier)
	}

	return matches
}

// CollectAuthEvents collects authentication related journal entries.
//
// First call:
//
//	events, cursor, err := CollectAuthEvents("")
//
// Following calls:
//
//	events, cursor, err = CollectAuthEvents(cursor)
//
// An empty cursor means that the latest initialJournalEntries entries
// are inspected. Afterwards --after-cursor is used.
func CollectAuthEvents(afterCursor string) ([]model.AuthEventLog, string, error) {
	if err := checkAuthLogSource(); err != nil {
		return nil, afterCursor, err
	}

	events, cursor, err := aggregateLog(afterCursor)
	if err != nil {
		return nil, afterCursor, fmt.Errorf("collect auth events: %w", err)
	}

	return events, cursor, nil
}

// checkAuthLogSource checks whether journalctl is available.
//
// The fallback files are detected already, but reading/parsing them
// still needs to be implemented.
func checkAuthLogSource() error {
	if _, err := exec.LookPath("journalctl"); err == nil {
		return nil
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf(
				"journalctl not available; fallback auth log %q exists but is not implemented yet",
				path,
			)
		}
	}

	return fmt.Errorf("no supported authentication log source found")
}

// aggregateLog reads journal entries.
//
// If afterCursor is empty, the latest entries are loaded.
// Otherwise only entries after the supplied cursor are requested.
//
// Either way journalMatches narrows the request to the authentication services,
// so the -n window holds that many auth entries rather than that many entries
// of whatever the machine logged last.
func aggregateLog(afterCursor string) ([]model.AuthEventLog, string, error) {
	var events []model.AuthEventLog

	// Keep the previous cursor if journalctl returns no new entries.
	lastCursor := afterCursor

	args := []string{
		"-o", "json",
		"--no-pager",
	}

	if afterCursor == "" {
		args = append(
			args,
			"-n",
			strconv.Itoa(initialJournalEntries),
		)
	} else {
		args = append(
			args,
			"--after-cursor",
			afterCursor,
		)
	}

	args = append(args, journalMatches()...)

	outputLogs, err := execCommand("journalctl", args...).Output()
	if err != nil {
		return nil, lastCursor, fmt.Errorf("execute journalctl: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(outputLogs))

	for scanner.Scan() {
		var journalEntry model.JournalEntry

		if err := json.Unmarshal(scanner.Bytes(), &journalEntry); err != nil {
			// journalctl encodes fields that are not valid UTF-8 as arrays of
			// byte values, which do not fit the string fields of JournalEntry.
			//
			// Such an entry is skipped rather than failing the poll. Aborting
			// here used to wedge authentication collection permanently: the
			// caller keeps its cursor on a failed poll, so every following poll
			// re-read the same entry and failed on it again.
			debugLog.Printf("skip unreadable journal entry: %v", err)

			// The cursor is a plain string even when a sibling field is not, so
			// recover it on its own and advance past the entry for good.
			var cursor model.Cursor

			if json.Unmarshal(scanner.Bytes(), &cursor) == nil && cursor.Cursor != "" {
				lastCursor = cursor.Cursor
			}

			continue
		}

		// Update the cursor before filtering. Even skipped entries have already
		// been consumed and must not be processed again on the next poll.
		if journalEntry.Cursor != "" {
			lastCursor = journalEntry.Cursor
		}

		event, skip, err := mapJournalEntry(&journalEntry)
		if err != nil {
			return nil, lastCursor, fmt.Errorf(
				"map journal entry: %w",
				err,
			)
		}

		if skip {
			continue
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, lastCursor, fmt.Errorf(
			"scan journal output: %w",
			err,
		)
	}

	return events, lastCursor, nil
}

// mapJournalEntry converts a relevant journal entry into an AuthEventLog.
//
// skip == true means that the journal entry is valid, but irrelevant
// for authentication monitoring.
func mapJournalEntry(
	entry *model.JournalEntry,
) (model.AuthEventLog, bool, error) {
	service, relevant := authEventFilter(entry)
	if !relevant {
		return model.AuthEventLog{}, true, nil
	}

	message := strings.TrimSpace(entry.Message)
	if message == "" {
		return model.AuthEventLog{}, true, nil
	}

	timestamp, err := strconv.ParseInt(
		entry.Timestamp,
		10,
		64,
	)
	if err != nil {
		// A single malformed journal entry must not stop the complete poll.
		debugLog.Printf(
			"skip %s auth entry with invalid journal timestamp %q: %v",
			service,
			entry.Timestamp,
			err,
		)
		return model.AuthEventLog{}, true, nil
	}

	event := model.AuthEventLog{
		Timestamp: time.UnixMicro(timestamp),
		Service:   service,
		Message:   message,

		// Carried through so the correlation can tie a local privilege change
		// back to the login session it happened inside.
		AuditSession: strings.TrimSpace(entry.AuditSession),
	}

	if !parseAuthMessage(&event) {
		return model.AuthEventLog{}, true, nil
	}

	return event, false, nil
}

// authEventFilter determines whether the journal entry belongs to
// one of the authentication services we are interested in.
//
// SYSLOG_IDENTIFIER is authoritative when it is present.
// _COMM is only used when SYSLOG_IDENTIFIER is empty.
func authEventFilter(entry *model.JournalEntry) (string, bool) {
	syslogIdentifier := strings.TrimSpace(entry.SyslogIdentifier)
	if syslogIdentifier != "" {
		return matchAuthService(syslogIdentifier)
	}

	return matchAuthService(entry.ProcessName)
}

// matchAuthService resolves a journal identifier to the service whose parser
// handles it, using the same table journalMatches builds its filter from.
func matchAuthService(identifier string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(identifier))

	if service, ok := authServices[name]; ok {
		return service, true
	}

	// A distribution may ship an sshd variant that authServices does not list.
	// Such an entry only arrives through _COMM, since the journalctl filter
	// enumerates identifiers by name, but classifying it costs nothing and the
	// alternative is dropping a genuine ssh authentication.
	if strings.HasPrefix(name, "sshd-") {
		return "sshd", true
	}

	return "", false
}

// parseAuthMessage dispatches the authentication message
// to the parser responsible for the corresponding service.
func parseAuthMessage(event *model.AuthEventLog) bool {
	switch event.Service {
	case "sshd":
		return parseSSHAuthMessage(event, event.Message)

	case "sudo":
		return parseSudoAuthMessage(event, event.Message)

	case "su":
		return parseSuAuthMessage(event, event.Message)

	case "login":
		return parseLoginAuthMessage(event, event.Message)

	default:
		return false
	}
}

// parseSSHAuthMessage parses authentication events generated by sshd.
func parseSSHAuthMessage(
	event *model.AuthEventLog,
	message string,
) bool {
	lowerMessage := strings.ToLower(message)

	switch {
	case strings.Contains(lowerMessage, "invalid user"):
		event.EventType = model.InvalidUser
		event.Success = false

	case strings.HasPrefix(lowerMessage, "accepted "):
		event.EventType = model.LoginSuccess
		event.Success = true

	case strings.HasPrefix(lowerMessage, "failed "):
		event.EventType = model.LoginFailed
		event.Success = false

	default:
		return false
	}

	populateSSHMetadata(event, message)
	return true
}

func populateSSHMetadata(event *model.AuthEventLog, message string) {
	match := sshUserFromRegex.FindStringSubmatch(message)
	if len(match) != 4 {
		match = sshInvalidUserFromRegex.FindStringSubmatch(message)
	}
	if len(match) != 4 {
		return
	}

	event.User = match[1]
	event.SourceIP = net.ParseIP(strings.Trim(match[2], "[]"))

	port, err := strconv.Atoi(match[3])
	if err == nil {
		event.SourcePort = port
	}
}

// parseSudoAuthMessage parses failed sudo authentication attempts.
func parseSudoAuthMessage(
	event *model.AuthEventLog,
	message string,
) bool {
	lowerMessage := strings.ToLower(message)

	switch {
	// Failed authentication
	case strings.Contains(
		lowerMessage,
		"authentication failure",
	):
		event.EventType = model.SudoFailed
		event.Success = false

		populateSudoMetadata(event, message)
		return true

	case strings.Contains(
		lowerMessage,
		"incorrect password attempt",
	):
		event.EventType = model.SudoFailed
		event.Success = false

		populateSudoMetadata(event, message)
		return true

	// Successful sudo execution
	case strings.Contains(message, "TTY=") &&
		strings.Contains(message, "USER=") &&
		strings.Contains(message, "COMMAND="):

		event.EventType = model.SudoSuccess
		event.Success = true

		populateSudoMetadata(event, message)
		return true

	default:
		return false
	}
}

func populateSudoMetadata(
	event *model.AuthEventLog,
	message string,
) {
	// Failed PAM authentication:
	//
	// pam_unix(sudo:auth): authentication failure;
	// ... user=alice
	if match := pamUserRegex.FindStringSubmatch(message); len(match) == 2 {
		event.User = match[1]
	}

	// Successful sudo command:
	//
	// alice : TTY=pts/2 ; PWD=... ;
	// USER=root ; COMMAND=/usr/bin/pacman ...
	if event.User == "" {
		if match := sudoActorRegex.FindStringSubmatch(message); len(match) == 2 {
			event.User = match[1]
		}
	}

	// Usually empty for local sudo.
	if match := rhostRegex.FindStringSubmatch(message); len(match) == 2 {
		event.SourceIP = net.ParseIP(
			strings.Trim(match[1], "[]"),
		)
	}

	populateTargetUser(event, message, sudoTargetRegex)
}

// populateTargetUser records the account a privilege change switched to.
//
// Two shapes carry it: sudo's own line ("USER=root"), matched by the caller's
// pattern, and the PAM session line both su and sudo emit ("session opened for
// user root(uid=0) by alice(uid=1000)").
func populateTargetUser(
	event *model.AuthEventLog,
	message string,
	own *regexp.Regexp,
) {
	if own != nil {
		if match := own.FindStringSubmatch(message); len(match) == 2 {
			event.TargetUser = match[1]
			return
		}
	}

	if match := loginSessionUserRegex.FindStringSubmatch(message); len(match) == 2 {
		event.TargetUser = match[1]
	}
}

// parseSuAuthMessage parses authentication events generated by su.
//
// su gets its own event types because a user switch is semantically different
// from a normal login. It is not called "privilege escalation" because su may
// also switch to a non-privileged account.
func parseSuAuthMessage(
	event *model.AuthEventLog,
	message string,
) bool {
	lowerMessage := strings.ToLower(message)

	switch {
	case strings.Contains(lowerMessage, "authentication failure"):
		event.EventType = model.SuFailed
		event.Success = false

	case strings.Contains(lowerMessage, "session opened for user"):
		event.EventType = model.SuSuccess
		event.Success = true

	default:
		return false
	}

	populateSuMetadata(event, message)
	return true
}

func populateSuMetadata(event *model.AuthEventLog, message string) {
	// Failed PAM authentication commonly carries user=<target>.
	if match := pamUserRegex.FindStringSubmatch(message); len(match) == 2 {
		event.User = match[1]
		event.TargetUser = match[1]

		return
	}

	// Successful su session messages commonly look like:
	// pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)
	if match := loginSessionUserRegex.FindStringSubmatch(message); len(match) == 2 {
		event.User = match[1]
	}

	populateTargetUser(event, message, nil)
}

// parseLoginAuthMessage parses local login authentication events.
func parseLoginAuthMessage(
	event *model.AuthEventLog,
	message string,
) bool {
	lowerMessage := strings.ToLower(message)

	switch {
	case strings.Contains(
		lowerMessage,
		"authentication failure",
	):
		event.EventType = model.LoginFailed
		event.Success = false

	case strings.Contains(
		lowerMessage,
		"failed login",
	):
		event.EventType = model.LoginFailed
		event.Success = false

	case strings.Contains(
		lowerMessage,
		"session opened for user",
	):
		event.EventType = model.LoginSuccess
		event.Success = true

	case strings.Contains(
		lowerMessage,
		"login on",
	):
		event.EventType = model.LoginSuccess
		event.Success = true

	default:
		return false
	}

	populateLoginMetadata(event, message)
	return true
}

func populateLoginMetadata(event *model.AuthEventLog, message string) {
	if match := pamUserRegex.FindStringSubmatch(message); len(match) == 2 {
		event.User = match[1]
	} else if match := loginSessionUserRegex.FindStringSubmatch(message); len(match) == 2 {
		event.User = match[1]
	}

	if match := rhostRegex.FindStringSubmatch(message); len(match) == 2 {
		event.SourceIP = net.ParseIP(strings.Trim(match[1], "[]"))
	}
}
