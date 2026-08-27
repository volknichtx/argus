package tui

import (
	"net"
	"testing"
	"time"

	models "github.com/volknichtx/argus/model"
)

func authAt(second int, ip string) models.AuthEventLog {
	event := models.AuthEventLog{
		Timestamp: time.Date(2026, 8, 27, 9, 53, second, 0, time.UTC),
		Service:   "sshd",
		EventType: models.LoginFailed,
		User:      "alice",
	}

	if ip != "" {
		event.SourceIP = net.ParseIP(ip)
		event.SourcePort = 51000
	}

	return event
}

// Regression: journald hands the events over oldest first, and the retention
// cap trims from that end. Rendering them in arrival order put the newest event
// below the fold of a full pane — the one event a live monitor exists to show.
func TestAuthRowsRenderNewestFirst(t *testing.T) {
	events := []models.AuthEventLog{authAt(1, ""), authAt(2, ""), authAt(3, "")}

	rows := authRows(events)

	if len(rows) != len(events) {
		t.Fatalf("rows = %d, want %d", len(rows), len(events))
	}

	want := []string{"09:53:03", "09:53:02", "09:53:01"}

	for i, stamp := range want {
		if got := rows[i][0].text; got != "2026-08-27 "+stamp {
			t.Errorf("row %d time = %q, want %q", i, got, stamp)
		}
	}
}

func TestAuthRowsOfNothingIsEmpty(t *testing.T) {
	if rows := authRows(nil); len(rows) != 0 {
		t.Errorf("rows = %d, want 0", len(rows))
	}
}

// The auth pane and the correlation engine have to agree about the same event.
// The engine refuses to grade loopback above normal, so painting a loopback
// origin amber here would have the two panes contradict each other.
func TestAuthSourceToneMatchesTheEngine(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want tone
	}{
		{name: "remote address", ip: "203.0.113.9", want: toneWarn},
		{name: "lan address", ip: "10.0.0.20", want: toneWarn},
		{name: "ipv4 loopback", ip: "127.0.0.1", want: toneMuted},
		{name: "ipv6 loopback", ip: "::1", want: toneMuted},
		{name: "no address at all", ip: "", want: toneMuted},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := authToRow(authAt(1, tc.ip))[5]

			if source.tone != tc.want {
				t.Errorf("source tone = %v, want %v", source.tone, tc.want)
			}

			if tc.ip == "" && source.text != "local" {
				t.Errorf("source text = %q, want %q", source.text, "local")
			}
		})
	}
}

// An escalation reaches the pane as its own event type, and it must not be
// rendered as an ordinary success.
func TestEscalationRowIsDistinguishable(t *testing.T) {
	event := models.AuthEventLog{
		Timestamp:    time.Date(2026, 8, 27, 9, 53, 49, 0, time.UTC),
		Service:      "su",
		EventType:    models.SuSuccess,
		User:         "root",
		TargetUser:   "root",
		AuditSession: "5",
		Success:      true,
	}

	r := authToRow(event)

	if got := r[1].text; got != "OK" {
		t.Errorf("status = %q, want OK", got)
	}

	if got := r[3].text; got != string(models.SuSuccess) {
		t.Errorf("event = %q, want %q", got, models.SuSuccess)
	}

	if r[3].tone == toneMuted {
		t.Error("a successful su to root renders in plain grey")
	}
}
