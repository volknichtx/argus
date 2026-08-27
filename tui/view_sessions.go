package tui

import (
	"github.com/volknichtx/argus/internal/netutil"
	models "github.com/volknichtx/argus/model"
)

func sessionToRow(session models.UserSession) row {
	pid := dim(unknownValue)
	if session.PID >= 0 {
		pid = dim(itoa(session.PID))
	}

	// Only a session that actually originates from another machine is worth a
	// second look. who(1) fills the field with "local", ":0" or a tmux pane for
	// local logins, so testing for a non-empty value would flag every session.
	source := dim(session.Source)
	if netutil.IsRemoteHost(session.Source) {
		source = toned(session.Source, toneWarn)
	}

	login := session.LoginDate + " " + session.LoginTime

	return row{
		txt(session.User),
		dim(session.TTY),
		dim(login),
		dim(session.Idle),
		pid,
		source,
	}
}
