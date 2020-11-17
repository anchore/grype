package ui

import (
	"os"
	"runtime"

	"github.com/anchore/grype/internal"

	"github.com/anchore/grype/internal/ui/etui"
	"golang.org/x/crypto/ssh/terminal"
)

// TODO: build tags to exclude options from windows

func Select(verbose, quiet bool) UI {
	var ui UI

	isStdinPiped := internal.IsPipedInput()
	isStdoutATty := terminal.IsTerminal(int(os.Stdout.Fd()))
	isStderrATty := terminal.IsTerminal(int(os.Stderr.Fd()))
	notATerminal := !isStderrATty && !isStdoutATty

	switch {
	case runtime.GOOS == "windows" || verbose || quiet || notATerminal || !isStderrATty || isStdinPiped:
		ui = LoggerUI
	default:
		ui = etui.OutputToEphemeralTUI
	}

	return ui
}
