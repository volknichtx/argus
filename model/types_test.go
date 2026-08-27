package model

import "testing"

// A login is not a privilege change, or one ssh session that ran sudo twice
// would read as three logins for the host it came from.
func TestOnlySuAndSudoArePrivilegeChanges(t *testing.T) {
	tests := []struct {
		eventType AuthEventType
		want      bool
	}{
		{eventType: LoginSuccess, want: false},
		{eventType: LoginFailed, want: false},
		{eventType: InvalidUser, want: false},
		{eventType: SudoSuccess, want: true},
		{eventType: SudoFailed, want: true},
		{eventType: SuSuccess, want: true},
		{eventType: SuFailed, want: true},
	}

	for _, tc := range tests {
		event := AuthEventLog{EventType: tc.eventType}

		if got := event.IsPrivilegeChange(); got != tc.want {
			t.Errorf("%s.IsPrivilegeChange() = %v, want %v", tc.eventType, got, tc.want)
		}
	}
}

// An escalation is a *successful* privilege change *to root*. Both halves
// matter: su and sudo also serve switches to ordinary service accounts, and a
// rejected attempt at root is a failure, not a gained privilege.
func TestEscalationNeedsSuccessAndRoot(t *testing.T) {
	tests := []struct {
		name  string
		event AuthEventLog
		want  bool
	}{
		{
			name:  "sudo to root",
			event: AuthEventLog{EventType: SudoSuccess, Success: true, TargetUser: "root"},
			want:  true,
		},
		{
			name:  "su to root",
			event: AuthEventLog{EventType: SuSuccess, Success: true, TargetUser: "root"},
			want:  true,
		},
		{
			name:  "sudo to a service account",
			event: AuthEventLog{EventType: SudoSuccess, Success: true, TargetUser: "backup"},
			want:  false,
		},
		{
			name:  "su with no target named",
			event: AuthEventLog{EventType: SuSuccess, Success: true},
			want:  false,
		},
		{
			name:  "failed sudo aimed at root",
			event: AuthEventLog{EventType: SudoFailed, TargetUser: "root"},
			want:  false,
		},
		{
			name:  "failed su aimed at root",
			event: AuthEventLog{EventType: SuFailed, TargetUser: "root"},
			want:  false,
		},
		{
			name:  "root logging in over ssh is a login, not an escalation",
			event: AuthEventLog{EventType: LoginSuccess, Success: true, User: "root", TargetUser: "root"},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.event.IsEscalation(); got != tc.want {
				t.Errorf("IsEscalation() = %v, want %v", got, tc.want)
			}
		})
	}
}
