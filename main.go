// Command argus is a live attack-surface monitor for Linux.
//
// It correlates listening ports, established connections, login sessions and
// authentication events per remote host, and grades each host by how much
// attention it deserves.
package main

import (
	"fmt"
	"os"

	"github.com/volknichtx/argus/collect"
	"github.com/volknichtx/argus/tui"

	tea "charm.land/bubbletea/v2"
)

// logEnvVar names a file the collectors append their diagnostics to. Unset is
// the normal case and discards them: anything written to the terminal while
// Bubble Tea owns it lands in the middle of a frame.
const logEnvVar = "ARGUS_LOG"

func main() {
	stopLogging, err := collect.LogToFile(os.Getenv(logEnvVar))
	if err != nil {
		fmt.Fprintln(os.Stderr, "argus:", err)
		os.Exit(1)
	}

	defer stopLogging()

	if _, err := tea.NewProgram(tui.New()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "argus:", err)
		os.Exit(1)
	}
}
