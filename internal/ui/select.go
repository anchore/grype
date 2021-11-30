//go:build linux || darwin
// +build linux darwin

package ui

import (
	"io"
	"os"

	"golang.org/x/term"
)

// TODO: build tags to exclude options from windows

// Select is responsible for determining the specific UI function given select user option, the current platform
// config values, and environment status (such as a TTY being present). The first UI in the returned slice of UIs
// is intended to be used and the UIs that follow are meant to be attempted only in a fallback posture when there
// are environmental problems (e.g. cannot write to the terminal). A writer is provided to capture the output of
// the final SBOM report.
func Select(verbose, quiet bool, reportWriter io.Writer) (uis []UI) {
	isStdoutATty := term.IsTerminal(int(os.Stdout.Fd()))
	isStderrATty := term.IsTerminal(int(os.Stderr.Fd()))
	notATerminal := !isStderrATty && !isStdoutATty

	switch {
	case verbose || quiet || notATerminal || !isStderrATty:
		uis = append(uis, NewLoggerUI(reportWriter))
	default:
		uis = append(uis, NewEphemeralTerminalUI(reportWriter), NewLoggerUI(reportWriter))
	}

	return uis
}
