// Package repoutil provides small helpers that resolve information about the
// grype repository working tree, primarily for use by build-time tooling and
// tests. The helpers shell out to git, so they are not appropriate for
// production runtime code.
package repoutil

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const modulePath = "github.com/anchore/grype"

// Root returns the absolute path of the grype repo's working tree root. It
// looks for the directory holding grype's go.mod above the current directory,
// and falls back to git rev-parse when there is none.
func Root() (string, error) {
	if root, ok := moduleRoot(); ok {
		return root, nil
	}
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

// moduleRoot walks up from the current directory to the go.mod that declares
// grype's module path.
func moduleRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		if declaresModule(filepath.Join(dir, "go.mod")) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func declaresModule(goMod string) bool {
	f, err := os.Open(goMod)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1] == modulePath
		}
	}
	return false
}
