package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bubbletea v1 queries the terminal from its package init; termrender must run first so that the
// query is written to stderr instead of stdout (see cmd/grype/internal/termrender).
func TestTermRenderInitializedBeforeBubbletea(t *testing.T) {
	// re-run this test binary (which shares the import graph of the grype binary) without running
	// any tests, and have the runtime trace package initialization order
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

	termrender := indexOf(order, "github.com/anchore/grype/cmd/grype/internal/termrender")
	bubbletea := indexOf(order, "github.com/charmbracelet/bubbletea")
	require.NotEqual(t, -1, termrender, "termrender init not found in init trace")
	require.NotEqual(t, -1, bubbletea, "bubbletea init not found in init trace")
	require.Less(t, termrender, bubbletea, "termrender must be initialized before bubbletea")
}

func indexOf(items []string, item string) int {
	for i, v := range items {
		if v == item {
			return i
		}
	}
	return -1
}
