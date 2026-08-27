package model

import (
	"net"
	"time"
)

/* Struct containing informations of ss -tulpn
	-t, --tcp 			--> Display TCP sockets
	-u, --udp 			--> Display UDP sockets
	-l, --listening 	--> Display only listening sockets
	-p, --processes 	--> Show processes using sockets
	-n, --numeric 		--> Do not try to resolve service names.
For further informations look at `man ss` by Alexey Kuznetsov.
Example output:

*/

// Port describes a listening TCP/UDP socket.
type Port struct {
	Protocol string
	Addr     string
	Port     string
	PID      int
	Process  string
	State    string
}

// Connection describes an established network connection.
type Connection struct {
	Protocol   string
	LocalAddr  string
	LocalPort  string
	RemoteAddr string
	RemotePort string
	PID        int
	Process    string
	State      string
}
type AuthEventType string

// When you add a constant here, also classify it in tui.toneForEventType and
// list it in tui.knownAuthEventTypes — an unclassified type silently renders
// in plain grey.
const (
	LoginSuccess AuthEventType = "login_success"
	LoginFailed  AuthEventType = "login_failed"
	InvalidUser  AuthEventType = "invalid_user"

	SudoSuccess AuthEventType = "sudo_success"
	SudoFailed  AuthEventType = "sudo_failed"

	SuSuccess AuthEventType = "su_success"
	SuFailed  AuthEventType = "su_failed"
)

type AuthEventLog struct {
	Timestamp  time.Time
	Service    string
	EventType  AuthEventType
	User       string
	SourceIP   net.IP
	SourcePort int
	Success    bool
	Message    string

	// TargetUser is the account a su or sudo event switched to, when the
	// message names one. It is what separates an escalation to root from a
	// switch to some unprivileged service account; User stays whatever the
	// service's own message is about.
	TargetUser string

	// AuditSession is the login session the event was produced in, taken from
	// the journal's _AUDIT_SESSION.
	//
	// It is the only thing tying a local privilege change back to the login it
	// happened inside: su and sudo carry no source address, so without this
	// there is nothing to join a remote host on.
	AuditSession string
}

// rootAccount is the unprivileged-to-privileged boundary this tool cares about.
// A su to some other account is a user switch, not an escalation.
const rootAccount = "root"

// IsPrivilegeChange reports whether this event is a su or sudo event: an
// account switch made from inside an existing login, rather than a login of its
// own. It is what keeps a privilege change out of a host's login count.
func (e AuthEventLog) IsPrivilegeChange() bool {
	switch e.EventType {
	case SudoSuccess, SudoFailed, SuSuccess, SuFailed:
		return true
	default:
		return false
	}
}

// IsEscalation reports whether this event is a successful privilege change to
// root.
//
// su and sudo both also serve switches to ordinary accounts, so the target
// account — not merely the service — is what makes an event an escalation.
func (e AuthEventLog) IsEscalation() bool {
	if !e.Success {
		return false
	}

	switch e.EventType {
	case SudoSuccess, SuSuccess:
		return e.TargetUser == rootAccount
	default:
		return false
	}
}

type Cursor struct {
	Cursor string `json:"__CURSOR"`
}

type JournalEntry struct {
	Timestamp        string `json:"__REALTIME_TIMESTAMP"`
	Cursor           string `json:"__CURSOR"`
	MessageID        string `json:"__MESSAGE_ID"`
	Message          string `json:"MESSAGE"`
	ProcessName      string `json:"_COMM"`
	PID              string `json:"_PID"`
	Hostname         string `json:"_HOSTNAME"`
	SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
	UID              string `json:"_UID"`
	GID              string `json:"_GID"`
	AuditSession     string `json:"_AUDIT_SESSION"`
}

type UserSession struct {
	User      string
	TTY       string
	LoginDate string
	LoginTime string
	Idle      string
	PID       int
	Source    string

	// ID is the logind session identifier, attached from loginctl by matching
	// the TTY. It is empty when logind does not know the session or loginctl is
	// unavailable, and it is what an auth event's AuditSession joins against.
	ID string
}
