// +build !windows

package ui

import (
	"github.com/anchore/grype/internal/ui/etui"
	"golang.org/x/crypto/ssh/terminal"
	"os"
)

func Select(verbose, quiet bool) UI {
	var ui UI

	isStdoutATty := terminal.IsTerminal(int(os.Stdout.Fd()))
	isStderrATty := terminal.IsTerminal(int(os.Stderr.Fd()))
	notATerminal := !isStderrATty && !isStdoutATty

	switch {
	case verbose || quiet || notATerminal || !isStderrATty:
		ui = LoggerUI
	default:
		ui = etui.OutputToEphemeralTUI
	}

	return ui
}
