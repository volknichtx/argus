package collect

import (
	"strings"
	"testing"
	"time"

	"github.com/volknichtx/argus/model"
)

// journalLine builds one line of `journalctl -o json` output.
func journalLine(cursor, timestamp, identifier, message string) string {
	return `{"__CURSOR":"` + cursor +
		`","__REALTIME_TIMESTAMP":"` + timestamp +
		`","SYSLOG_IDENTIFIER":"` + identifier +
		`","MESSAGE":"` + message + `"}`
}

// Without a match list journalctl returns the whole system journal: the initial
// window fills with unrelated entries and every poll parses the machine's
// complete journal delta only to throw most of it away.
func TestJournalRequestIsFilteredToAuthServices(t *testing.T) {
	run := fakeCommand(t, journalLine("c1", "1756240000000000", "sshd",
		"Accepted password for alice from 192.0.2.20 port 49910 ssh2")+"\n", 0)

	if _, _, err := aggregateLog(""); err != nil {
		t.Fatalf("aggregateLog(): %v", err)
	}

	if got := run.name(); got != "journalctl" {
		t.Errorf("ran %q, want journalctl", got)
	}

	for identifier := range authServices {
		if !run.arg("SYSLOG_IDENTIFIER=" + identifier) {
			t.Errorf("journalctl was not matched on identifier %q: %v", identifier, run.args())
		}

		if !run.arg("_COMM=" + identifier) {
			t.Errorf("journalctl was not matched on command %q: %v", identifier, run.args())
		}
	}

	// The two groups are ORed by a single "+". More than one would change the
	// grouping, none would AND the identifier and command matches together and
	// return nothing at all.
	plus := 0

	for _, arg := range run.args() {
		if arg == "+" {
			plus++
		}
	}

	if plus != 1 {
		t.Errorf("match list has %d group separators, want exactly 1: %v", plus, run.args())
	}
}

// The journalctl filter must not be narrower than the classifier, or entries
// would be discarded before anything could classify them.
func TestJournalFilterCoversEveryClassifiedService(t *testing.T) {
	matches := journalMatches()

	for identifier := range authServices {
		service, ok := matchAuthService(identifier)
		if !ok {
			t.Fatalf("identifier %q is fetched but not classified", identifier)
		}

		if service == "" {
			t.Errorf("identifier %q classified as the empty service", identifier)
		}

		found := false

		for _, match := range matches {
			if match == "SYSLOG_IDENTIFIER="+identifier {
				found = true
			}
		}

		if !found {
			t.Errorf("identifier %q is classified but never fetched", identifier)
		}
	}
}

// An empty cursor seeds from the newest entries; afterwards only the delta is
// requested. Getting this wrong either re-reads the journal forever or skips it.
func TestJournalWindowDependsOnCursor(t *testing.T) {
	t.Run("seeding", func(t *testing.T) {
		run := fakeCommand(t, "", 0)

		if _, _, err := aggregateLog(""); err != nil {
			t.Fatalf("aggregateLog(): %v", err)
		}

		if !run.arg("-n") {
			t.Errorf("seeding poll did not bound the window: %v", run.args())
		}

		if run.arg("--after-cursor") {
			t.Errorf("seeding poll asked for a delta: %v", run.args())
		}
	})

	t.Run("delta", func(t *testing.T) {
		run := fakeCommand(t, "", 0)

		if _, _, err := aggregateLog("cursor-1"); err != nil {
			t.Fatalf("aggregateLog(): %v", err)
		}

		if !run.arg("--after-cursor") || !run.arg("cursor-1") {
			t.Errorf("delta poll did not pass the cursor: %v", run.args())
		}

		if run.arg("-n") {
			t.Errorf("delta poll re-bounded the window: %v", run.args())
		}
	})
}

// Regression: journalctl encodes fields that are not valid UTF-8 as arrays of
// byte values. Failing the poll on one such entry wedged authentication
// collection for the rest of the session, because the caller keeps its cursor
// when a poll fails and every following poll re-read the same entry.
func TestUnreadableJournalEntryIsSkippedNotFatal(t *testing.T) {
	output := strings.Join([]string{
		journalLine("c1", "1756240000000000", "sshd",
			"Accepted password for alice from 192.0.2.20 port 49910 ssh2"),
		`{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1756240001000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[72,105,255]}`,
		journalLine("c3", "1756240002000000", "sshd",
			"Failed password for root from 192.0.2.30 port 51000 ssh2"),
	}, "\n") + "\n"

	fakeCommand(t, output, 0)

	events, cursor, err := aggregateLog("")
	if err != nil {
		t.Fatalf("one unreadable entry failed the whole poll: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("events = %d, want the two readable entries", len(events))
	}

	if cursor != "c3" {
		t.Errorf("cursor = %q, want c3", cursor)
	}
}

// Even when the unreadable entry is the last one in the window, its cursor has
// to be recovered on its own, or the next poll re-reads it forever.
func TestUnreadableTrailingEntryStillAdvancesTheCursor(t *testing.T) {
	output := journalLine("c1", "1756240000000000", "sshd",
		"Accepted password for alice from 192.0.2.20 port 49910 ssh2") + "\n" +
		`{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1756240001000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[255]}` + "\n"

	fakeCommand(t, output, 0)

	_, cursor, err := aggregateLog("")
	if err != nil {
		t.Fatalf("aggregateLog(): %v", err)
	}

	if cursor != "c2" {
		t.Errorf("cursor = %q, want c2: the poll must advance past the bad entry", cursor)
	}
}

// Entries that are readable but irrelevant still move the cursor: they have
// been consumed, and holding the cursor back would re-read a growing window on
// every tick.
func TestFilteredEntriesStillAdvanceTheCursor(t *testing.T) {
	output := strings.Join([]string{
		journalLine("c1", "1756240000000000", "sshd", "Server listening on 0.0.0.0 port 22."),
		journalLine("c2", "1756240001000000", "systemd", "Started something unrelated."),
	}, "\n") + "\n"

	fakeCommand(t, output, 0)

	events, cursor, err := aggregateLog("")
	if err != nil {
		t.Fatalf("aggregateLog(): %v", err)
	}

	if len(events) != 0 {
		t.Errorf("events = %d, want none: neither entry is an auth event", len(events))
	}

	if cursor != "c2" {
		t.Errorf("cursor = %q, want c2", cursor)
	}
}

// A failing journalctl must not move the cursor, or the events of that window
// are lost for good.
func TestFailedPollKeepsTheCursor(t *testing.T) {
	fakeCommand(t, "", 1)

	_, cursor, err := aggregateLog("cursor-1")
	if err == nil {
		t.Fatal("a failing journalctl produced no error")
	}

	if cursor != "cursor-1" {
		t.Errorf("cursor = %q, want the previous one kept", cursor)
	}
}

func TestCollectAuthEventsParsesJournal(t *testing.T) {
	fakeCommand(t, journalLine("c1", "1756240000000000", "sshd",
		"Accepted password for alice from 192.0.2.20 port 49910 ssh2")+"\n", 0)

	events, cursor, err := CollectAuthEvents("")
	if err != nil {
		t.Fatalf("CollectAuthEvents(): %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}

	event := events[0]

	if event.EventType != model.LoginSuccess || !event.Success {
		t.Errorf("event = %+v, want a successful login", event)
	}

	if got := event.SourceIP.String(); got != "192.0.2.20" {
		t.Errorf("source = %q, want 192.0.2.20", got)
	}

	if !event.Timestamp.Equal(time.UnixMicro(1756240000000000)) {
		t.Errorf("timestamp = %v, want the journal's realtime stamp", event.Timestamp)
	}

	if cursor != "c1" {
		t.Errorf("cursor = %q, want c1", cursor)
	}
}

// A machine with neither journalctl nor a readable fallback has to say so,
// rather than reporting that nobody ever authenticated.
func TestCheckAuthLogSource(t *testing.T) {
	t.Run("journalctl present", func(t *testing.T) {
		if _, err := execCommand("journalctl", "--version").Output(); err != nil {
			t.Skip("no journalctl on this machine")
		}

		if err := checkAuthLogSource(); err != nil {
			t.Errorf("checkAuthLogSource() = %v, want nil", err)
		}
	})

	t.Run("no journalctl but a fallback file", func(t *testing.T) {
		t.Setenv("PATH", "")

		previous := paths
		t.Cleanup(func() { paths = previous })

		// An existing file that is not an auth log stands in for one: the point
		// is that the fallback is detected and reported as unimplemented.
		paths = []string{t.TempDir()}

		err := checkAuthLogSource()
		if err == nil {
			t.Fatal("checkAuthLogSource() = nil, want the unimplemented fallback error")
		}

		if !strings.Contains(err.Error(), "not implemented") {
			t.Errorf("error = %q, want it to name the unimplemented fallback", err)
		}
	})

	t.Run("no source at all", func(t *testing.T) {
		t.Setenv("PATH", "")

		previous := paths
		t.Cleanup(func() { paths = previous })

		paths = []string{"/nonexistent/argus/auth.log"}

		if err := checkAuthLogSource(); err == nil {
			t.Fatal("checkAuthLogSource() = nil, want an error")
		}
	})
}

func TestMapJournalEntry(t *testing.T) {
	tests := []struct {
		name      string
		entry     model.JournalEntry
		wantSkip  bool
		wantType  model.AuthEventType
		rationale string
	}{
		{
			name: "relevant sshd login",
			entry: model.JournalEntry{
				Timestamp:        "1756240000000000",
				SyslogIdentifier: "sshd",
				Message:          "Accepted password for alice from 192.0.2.20 port 49910 ssh2",
			},
			wantType: model.LoginSuccess,
		},
		{
			name: "unrelated service",
			entry: model.JournalEntry{
				Timestamp:        "1756240000000000",
				SyslogIdentifier: "systemd",
				Message:          "Started something.",
			},
			wantSkip:  true,
			rationale: "not an authentication service",
		},
		{
			name: "empty message",
			entry: model.JournalEntry{
				Timestamp:        "1756240000000000",
				SyslogIdentifier: "sshd",
				Message:          "   ",
			},
			wantSkip:  true,
			rationale: "nothing to parse",
		},
		{
			name: "unparseable timestamp",
			entry: model.JournalEntry{
				Timestamp:        "not-a-timestamp",
				SyslogIdentifier: "sshd",
				Message:          "Accepted password for alice from 192.0.2.20 port 49910 ssh2",
			},
			wantSkip:  true,
			rationale: "an event without a time cannot be placed",
		},
		{
			name: "relevant service, irrelevant message",
			entry: model.JournalEntry{
				Timestamp:        "1756240000000000",
				SyslogIdentifier: "sshd",
				Message:          "Server listening on 0.0.0.0 port 22.",
			},
			wantSkip:  true,
			rationale: "sshd says plenty that is not authentication",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry

			event, skip, err := mapJournalEntry(&entry)
			if err != nil {
				t.Fatalf("mapJournalEntry(): %v", err)
			}

			if skip != tc.wantSkip {
				t.Fatalf("skip = %v, want %v (%s)", skip, tc.wantSkip, tc.rationale)
			}

			if tc.wantSkip {
				return
			}

			if event.EventType != tc.wantType {
				t.Errorf("EventType = %q, want %q", event.EventType, tc.wantType)
			}
		})
	}
}

// SYSLOG_IDENTIFIER is what the service calls itself and wins; _COMM is the
// binary name and only fills in when the identifier is absent.
func TestAuthEventFilterPrefersTheSyslogIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		entry       model.JournalEntry
		wantService string
		wantOK      bool
	}{
		{
			name:        "identifier decides",
			entry:       model.JournalEntry{SyslogIdentifier: "sshd", ProcessName: "sudo"},
			wantService: "sshd",
			wantOK:      true,
		},
		{
			name:        "identifier rejects even when the command would match",
			entry:       model.JournalEntry{SyslogIdentifier: "cron", ProcessName: "sudo"},
			wantService: "",
			wantOK:      false,
		},
		{
			name:        "command fills in for a missing identifier",
			entry:       model.JournalEntry{SyslogIdentifier: "  ", ProcessName: "sudo"},
			wantService: "sudo",
			wantOK:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry

			service, ok := authEventFilter(&entry)

			if ok != tc.wantOK || service != tc.wantService {
				t.Errorf("authEventFilter() = %q, %v, want %q, %v",
					service, ok, tc.wantService, tc.wantOK)
			}
		})
	}
}

func TestMatchAuthService(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		want       string
		wantOK     bool
	}{
		{name: "sshd", identifier: "sshd", want: "sshd", wantOK: true},
		{name: "split sshd session binary", identifier: "sshd-session", want: "sshd", wantOK: true},
		{name: "split sshd auth binary", identifier: "sshd-auth", want: "sshd", wantOK: true},
		{name: "unlisted sshd variant", identifier: "sshd-future", want: "sshd", wantOK: true},
		{name: "sudo", identifier: "sudo", want: "sudo", wantOK: true},
		{name: "su", identifier: "su", want: "su", wantOK: true},
		{name: "login", identifier: "login", want: "login", wantOK: true},
		{name: "case and padding are normalized", identifier: "  SSHD  ", want: "sshd", wantOK: true},
		{name: "unrelated service", identifier: "systemd", wantOK: false},
		{name: "empty", identifier: "", wantOK: false},
		{
			// Guard against a prefix rule that would swallow half the journal.
			name:       "unrelated service starting with su",
			identifier: "supervisord",
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := matchAuthService(tc.identifier)

			if ok != tc.wantOK || got != tc.want {
				t.Errorf("matchAuthService(%q) = %q, %v, want %q, %v",
					tc.identifier, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
