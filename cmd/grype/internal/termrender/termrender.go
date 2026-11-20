// Package termrender binds the default lipgloss renderer to stderr during package init, so the terminal
// queries bubbletea v1 makes from its own init (lipgloss.HasDarkBackground) don't end up on stdout ahead of
// report output. Go initializes ready packages in import path order, so this runs before bubbletea (guarded by
// TestTermRenderInitializedBeforeBubbletea). cmd/grype/cli rebinds the renderer to stdout before any report.
package termrender

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

func init() {
	lipgloss.SetDefaultRenderer(lipgloss.NewRenderer(os.Stderr))
}
