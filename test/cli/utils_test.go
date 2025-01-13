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

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func getFixtureImage(tb testing.TB, fixtureImageName string) string {
	tb.Helper()

	imagetest.GetFixtureImage(tb, "docker-archive", fixtureImageName)
	return imagetest.GetFixtureImageTarPath(tb, fixtureImageName)
}

func getGrypeCommand(tb testing.TB, args ...string) *exec.Cmd {
	tb.Helper()
	argsWithConfig := args
	if !grypeCommandHasConfigArg(argsWithConfig...) {
		argsWithConfig = append(
			[]string{"-c", "../grype-test-config.yaml"},
			args...,
		)
	}

	return exec.Command(
		getGrypeSnapshotLocation(tb, runtime.GOOS),
		argsWithConfig...,
	)
}

func grypeCommandHasConfigArg(args ...string) bool {
	for _, arg := range args {
		if arg == "-c" || arg == "--config" {
			return true
		}
	}
	return false
}

func getGrypeSnapshotLocation(t testing.TB, goOS string) string {
	// GRYPE_BINARY_LOCATION is the absolute path to the snapshot binary
	const envKey = "GRYPE_BINARY_LOCATION"
	if os.Getenv(envKey) != "" {
		return os.Getenv(envKey)
	}
	loc := getGrypeBinaryLocationByOS(t, goOS)
	buildBinary(t, loc)
	_ = os.Setenv(envKey, loc)
	return loc
}

func getGrypeBinaryLocationByOS(t testing.TB, goOS string) string {
	// note: for amd64 we need to update the snapshot location with the v1 suffix
	// see : https://goreleaser.com/customization/build/#why-is-there-a-_v1-suffix-on-amd64-builds
	archPath := runtime.GOARCH
	if runtime.GOARCH == "amd64" {
		archPath = fmt.Sprintf("%s_v1", archPath)
	}
	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "darwin", "linux":
		return path.Join(repoRoot(t), fmt.Sprintf("snapshot/%s-build_%s_%s/grype", goOS, goOS, archPath))
	default:
		t.Fatalf("unsupported OS: %s", runtime.GOOS)
	}
	return ""
}

func buildBinary(t testing.TB, loc string) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(repoRoot(t)))
	defer func() {
		require.NoError(t, os.Chdir(wd))
	}()
	t.Log("Building grype...")
	c := exec.Command("go", "build", "-o", loc, "./cmd/grype")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	require.NoError(t, c.Run())
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
