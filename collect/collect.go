// Package collect runs the external tools argus reads its data from — ss, who
// and journalctl — and turns their output into models.
//
// Everything in here does I/O. Nothing in here decides what a finding means:
// that is the correlation engine's job, and keeping the split sharp is what
// lets the engine stay a pure function.
package collect

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

// execCommand is the seam the tests replace to run a recorded fixture instead
// of the real ss, who or journalctl. Production always goes through
// exec.Command.
var execCommand = exec.Command

// debugLog receives the diagnostics a collector emits when it skips input it
// could not parse.
//
// It discards by default on purpose. The collectors run inside a Bubble Tea
// program that owns the terminal, so a stray write to stderr lands in the
// middle of a rendered frame and corrupts the display. Diagnostics only become
// visible when the caller asks for them with LogToFile.
var debugLog = log.New(io.Discard, "", log.LstdFlags)

// logFileMode keeps the log readable only by its owner: it records which
// addresses reached this machine, which is exactly the kind of detail that
// should not become world-readable.
const logFileMode = 0o600

// LogToFile routes collector diagnostics to the file at path, appending to it,
// and returns the function that stops the logging again.
//
// An empty path is the normal case and disables logging entirely, which is why
// it is not an error: the caller can hand a possibly-unset environment variable
// straight to it.
func LogToFile(path string) (stop func(), err error) {
	if path == "" {
		return func() {}, nil
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFileMode)
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", path, err)
	}

	debugLog.SetOutput(file)

	return func() {
		debugLog.SetOutput(io.Discard)
		file.Close()
	}, nil
}
