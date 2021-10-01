package ui

import (
	"os"
	"runtime"

	"golang.org/x/crypto/ssh/terminal"
)

// TODO: build tags to exclude options from windows

// Select is responsible for determining the specific UI function given select user option, the current platform
// config values, and environment status (such as a TTY being present).
func Select(verbose, quiet bool) UI {
	var ui UI

	isStdoutATty := terminal.IsTerminal(int(os.Stdout.Fd()))
	isStderrATty := terminal.IsTerminal(int(os.Stderr.Fd()))
	notATerminal := !isStderrATty && !isStdoutATty

	switch {
	case runtime.GOOS == "windows" || verbose || quiet || notATerminal || !isStderrATty:
		ui = NewLoggerUI()
	default:
		ui = NewEphemeralTerminalUI()
	}

	return ui
}
