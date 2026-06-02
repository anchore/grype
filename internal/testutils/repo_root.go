package testutils

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoRoot returns the absolute path of the grype repo's working tree root via
// git rev-parse. Use this from test or build-time tooling that needs paths
// relative to the repo root. Not for production code: shelling out to git would
// be a surprising dependency at runtime.
func RepoRoot() (string, error) {
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
