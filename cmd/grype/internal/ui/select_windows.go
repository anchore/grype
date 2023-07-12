//go:build windows
// +build windows

package ui

import "github.com/anchore/clio"

// Select is responsible for determining the specific UI function given select user option, the current platform
// config values, and environment status (such as a TTY being present). The first UI in the returned slice of UIs
// is intended to be used and the UIs that follow are meant to be attempted only in a fallback posture when there
// are environmental problems (e.g. cannot write to the terminal). A writer is provided to capture the output of
// the final SBOM report.
func Select(verbose, quiet bool) (uis []clio.UI) {
	return append(uis, None(quiet))
}
