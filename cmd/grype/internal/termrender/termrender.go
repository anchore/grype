// Package termrender keeps terminal queries made during package initialization off of stdout.
//
// bubbletea v1 calls lipgloss.HasDarkBackground() from its package init. With the default
// lipgloss renderer (bound to stdout) this writes terminal queries (OSC 11 and a cursor
// position request) to stdout whenever stdout is a TTY, which corrupts report output such
// as `grype db list -o json` when it is captured through a pty (e.g. `docker run -t ... | jq`).
//
// Binding the default renderer to stderr during init moves the queries to stderr, where
// grype's UI is drawn anyway. The default renderer is bound to stdout again when the UI is
// constructed (see cmd/grype/cli), before any report is written.
//
// This package must be initialized before github.com/charmbracelet/bubbletea. Go initializes
// packages whose dependencies are ready in import path order, and this import path sorts
// before github.com/charmbracelet/*. TestTermRenderInitializedBeforeBubbletea guards this.
package termrender

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

func init() {
	lipgloss.SetDefaultRenderer(lipgloss.NewRenderer(os.Stderr))
}
