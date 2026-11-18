package main

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// termrender must initialize before bubbletea (see cmd/grype/internal/termrender).
func TestTermRenderInitializedBeforeBubbletea(t *testing.T) {
	// re-run this test binary (same import graph as grype) and trace package initialization
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // re-executes this test binary
	cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	var order []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "init" {
			order = append(order, fields[1])
		}
	}

	termrender := slices.Index(order, "github.com/anchore/grype/cmd/grype/internal/termrender")
	bubbletea := slices.Index(order, "github.com/charmbracelet/bubbletea")
	require.NotEqual(t, -1, termrender, "termrender init not found in init trace")
	require.NotEqual(t, -1, bubbletea, "bubbletea init not found in init trace")
	require.Less(t, termrender, bubbletea, "termrender must be initialized before bubbletea")
}
