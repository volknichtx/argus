package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// recordedRun is what a faked ss/who/journalctl/loginctl was asked to do. A
// collector may run more than one program, so every invocation is kept.
type recordedRun struct {
	// runs holds one full command line per invocation, name first.
	runs [][]string
}

// name is the program of the first invocation, which is the collector's
// primary tool.
func (r recordedRun) name() string {
	if len(r.runs) == 0 || len(r.runs[0]) == 0 {
		return ""
	}

	return r.runs[0][0]
}

// args is the first invocation's full command line, kept for error messages.
func (r recordedRun) args() []string {
	if len(r.runs) == 0 {
		return nil
	}

	return r.runs[0]
}

// arg reports whether any recorded invocation carried the given argument.
func (r recordedRun) arg(want string) bool {
	for _, run := range r.runs {
		for _, got := range run[1:] {
			if got == want {
				return true
			}
		}
	}

	return false
}

// ranProgram reports whether the given program was invoked at all.
func (r recordedRun) ranProgram(name string) bool {
	for _, run := range r.runs {
		if len(run) > 0 && run[0] == name {
			return true
		}
	}

	return false
}

// fakeCommand points execCommand at a subprocess that prints stdout and exits
// with exitCode, so a collector can be driven against recorded tool output
// instead of whatever this machine happens to be doing.
//
// Every program gets the same canned output. Use fakeCommands when a collector
// runs more than one tool and they need different answers.
func fakeCommand(t *testing.T, stdout string, exitCode int) *recordedRun {
	t.Helper()

	return fakeCommands(t, map[string]fakeResult{"": {stdout: stdout, exitCode: exitCode}})
}

// fakeResult is what a faked program prints and exits with.
type fakeResult struct {
	stdout   string
	exitCode int
}

// fakeCommands replaces execCommand with per-program canned results, keyed by
// program name. The empty key is the fallback for anything not named.
func fakeCommands(t *testing.T, results map[string]fakeResult) *recordedRun {
	t.Helper()

	run := &recordedRun{}

	previous := execCommand
	t.Cleanup(func() { execCommand = previous })

	execCommand = func(name string, args ...string) *exec.Cmd {
		run.runs = append(run.runs, append([]string{name}, args...))

		result, ok := results[name]
		if !ok {
			result = results[""]
		}

		cmd := exec.Command(os.Args[0], "-test.run=TestCollectorHelperProcess")
		cmd.Env = append(
			os.Environ(),
			helperMarker+"=1",
			helperStdout+"="+result.stdout,
			helperExit+"="+strconv.Itoa(result.exitCode),
		)

		return cmd
	}

	return run
}

const (
	helperMarker = "ARGUS_TEST_HELPER"
	helperStdout = "ARGUS_TEST_HELPER_STDOUT"
	helperExit   = "ARGUS_TEST_HELPER_EXIT"
)

// TestCollectorHelperProcess is not a test. It is the subprocess fakeCommand
// runs in place of ss, who or journalctl, and it does nothing at all unless the
// marker environment variable says it was started for that purpose.
func TestCollectorHelperProcess(t *testing.T) {
	if os.Getenv(helperMarker) != "1" {
		return
	}

	os.Stdout.WriteString(os.Getenv(helperStdout))

	code, err := strconv.Atoi(os.Getenv(helperExit))
	if err != nil {
		code = 0
	}

	os.Exit(code)
}

// Diagnostics are discarded until a caller asks for them, because the
// collectors run inside a program that owns the terminal.
func TestLogToFileWritesOnlyWhenAsked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.log")

	// An unset ARGUS_LOG is the normal case, not an error.
	stop, err := LogToFile("")
	if err != nil {
		t.Fatalf("LogToFile(\"\") returned an error: %v", err)
	}

	debugLog.Printf("discarded")
	stop()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("logging to no file created %q", path)
	}

	stop, err = LogToFile(path)
	if err != nil {
		t.Fatalf("LogToFile(%q): %v", path, err)
	}

	debugLog.Printf("recorded marker")
	stop()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	if !strings.Contains(string(data), "recorded marker") {
		t.Errorf("log file = %q, want it to contain the message", data)
	}

	// Once stopped, nothing more may reach the file.
	before := len(data)

	debugLog.Printf("must not be written")

	if data, err = os.ReadFile(path); err != nil {
		t.Fatalf("re-read log: %v", err)
	}

	if len(data) != before {
		t.Errorf("log grew after stop: %q", data)
	}
}

// The log records which addresses reached this machine, so it must not be
// world-readable.
func TestLogToFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus.log")

	stop, err := LogToFile(path)
	if err != nil {
		t.Fatalf("LogToFile(%q): %v", path, err)
	}

	defer stop()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}

	if got := info.Mode().Perm(); got != logFileMode {
		t.Errorf("log file mode = %04o, want %04o", got, logFileMode)
	}
}

// A log path that cannot be opened is reported rather than swallowed: the user
// asked for diagnostics and would otherwise never learn they are missing.
func TestLogToFileReportsUnusablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-directory", "argus.log")

	stop, err := LogToFile(path)
	if err == nil {
		stop()
		t.Fatalf("LogToFile(%q) succeeded, want an error", path)
	}

	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the path", err)
	}
}
