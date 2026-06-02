// Package repoutil provides small helpers that resolve information about the
// grype repository working tree, primarily for use by build-time tooling and
// tests. The helpers shell out to git, so they are not appropriate for
// production runtime code.
package repoutil

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Root returns the absolute path of the grype repo's working tree root via
// git rev-parse.
func Root() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("unable to find repo root dir: %w", err)
	}
	abs, err := filepath.Abs(strings.TrimSpace(string(out)))
	if err != nil {
		return "", fmt.Errorf("unable to get abs path to repo root: %w", err)
	}
	return abs, nil
}
