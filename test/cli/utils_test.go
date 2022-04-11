package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/stretchr/testify/require"
)

func getFixtureImage(tb testing.TB, fixtureImageName string) string {
	tb.Helper()

	imagetest.GetFixtureImage(tb, "docker-archive", fixtureImageName)
	return imagetest.GetFixtureImageTarPath(tb, fixtureImageName)
}

func getGrypeCommand(tb testing.TB, args ...string) *exec.Cmd {
	tb.Helper()

	return exec.Command(
		getGrypeSnapshotLocation(tb, runtime.GOOS),
		append(
			[]string{"-c", "../grype-test-config.yaml"},
			args...,
		)...,
	)
}

func getGrypeSnapshotLocation(tb testing.TB, goOS string) string {
	if os.Getenv("GRYPE_BINARY_LOCATION") != "" {
		// GRYPE_BINARY_LOCATION is the absolute path to the snapshot binary
		return os.Getenv("GRYPE_BINARY_LOCATION")
	}

	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "darwin":
		return path.Join(repoRoot(tb), fmt.Sprintf("snapshot/darwin-build_darwin_%s/grype", runtime.GOARCH))
	case "linux":
		return path.Join(repoRoot(tb), fmt.Sprintf("snapshot/linux-build_linux_%s/grype", runtime.GOARCH))
	default:
		tb.Fatalf("unsupported OS: %s", runtime.GOOS)
	}
	return ""
}

func getDockerRunCommand(tb testing.TB, args ...string) *exec.Cmd {
	tb.Helper()

	return exec.Command(
		"docker",
		append(
			[]string{"run"},
			args...,
		)...,
	)
}

func runGrype(tb testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	tb.Helper()

	cmd := getGrypeCommand(tb, args...)
	if env == nil {
		env = make(map[string]string)
	}

	// we should not have tests reaching out for app update checks
	env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"

	stdout, stderr := runCommand(cmd, env)
	return cmd, stdout, stderr
}

func runCommand(cmd *exec.Cmd, env map[string]string) (string, string) {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	cmd.Run()

	return stdout.String(), stderr.String()
}

func envMapToSlice(env map[string]string) (envList []string) {
	for key, val := range env {
		if key == "" {
			continue
		}
		envList = append(envList, fmt.Sprintf("%s=%s", key, val))
	}
	return
}

func repoRoot(tb testing.TB) string {
	tb.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		tb.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		tb.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}

func attachFileToCommandStdin(tb testing.TB, file io.Reader, command *exec.Cmd) {
	tb.Helper()

	b, err := io.ReadAll(file)
	require.NoError(tb, err)
	command.Stdin = bytes.NewReader(b)
}

func assertCommandExecutionSuccess(t testing.TB, cmd *exec.Cmd) {
	_, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatal(exitErr)
		}

		t.Fatalf("unable to run command %q: %v", cmd, err)
	}
}

func testWithTimeout(t *testing.T, name string, timeout time.Duration, test func(*testing.T)) {
	done := make(chan bool)
	go func() {
		t.Run(name, test)
		done <- true
	}()

	select {
	case <-time.After(timeout):
		t.Fatal("test timed out")
	case <-done:
	}
}
