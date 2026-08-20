package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/dbtest"
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
		// note: this is an absolute path since the working directory may have been changed by
		// building the snapshot binary
		argsWithConfig = append(
			[]string{"-c", filepath.Join(repoRoot(tb), "test", "grype-test-config.yaml")},
			args...,
		)
	}

	return exec.Command(
		getGrypeSnapshotLocation(tb, runtime.GOOS, runtime.GOARCH),
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

func getGrypeSnapshotLocation(t testing.TB, goOS, goArch string) string {
	loc := getGrypeBinaryLocationByOS(t, goOS, goArch)
	// GRYPE_BINARY_LOCATION is the absolute path to the snapshot binary
	const envKey = "GRYPE_BINARY_LOCATION"
	if os.Getenv(envKey) != "" {
		// we were run from a snapshot test, so we already have a snapshot binary
		return loc
	}
	// if this was built locally
	if os.Getenv(loc) != "" {
		return loc
	}
	buildBinary(t, loc, goOS, goArch)
	_ = os.Setenv(loc, loc)
	return loc
}

func getGrypeBinaryLocationByOS(t testing.TB, goOS, goArch string) string {
	// note: for amd64 we need to update the snapshot location with the v1 suffix
	// see : https://goreleaser.com/customization/build/#why-is-there-a-_v1-suffix-on-amd64-builds
	if goArch == "amd64" {
		goArch = fmt.Sprintf("%s_v1", goArch)
	}
	executable := "grype"
	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "windows":
		executable += ".exe"
		fallthrough
	case "darwin", "linux":
		return filepath.Join(repoRoot(t), "snapshot", fmt.Sprintf("%s-build_%s_%s", goOS, goOS, goArch), executable)
	default:
		t.Fatalf("unsupported OS: %s", runtime.GOOS)
	}
	return ""
}

func buildBinary(t testing.TB, loc, goOS, goArch string) {
	t.Logf("Building grype for %s %s...", goOS, goArch)
	c := exec.Command("go", "build", "-o", loc, "./cmd/grype")
	// note: set the build directory on the command instead of changing the working directory of the
	// test process itself -- tests (and imagetest fixtures) resolve paths relative to ./test/cli
	c.Dir = repoRoot(t)
	environ := append(os.Environ(), "CGO_ENABLED=0")
	if goOS != runtime.GOOS || goArch != runtime.GOARCH {
		environ = append(environ, fmt.Sprintf("GOOS=%s", goOS), fmt.Sprintf("GOARCH=%s", goArch))
	}
	c.Env = environ
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	require.NoError(t, c.Run())
}

// getDockerRunCommandContext gets a command to run docker that allows interrupting the container,
// which allows --rm to clean it up instead of leaving it running
func getDockerRunCommandContext(ctx context.Context, tb testing.TB, args ...string) *exec.Cmd {
	tb.Helper()

	cmd := exec.CommandContext(
		ctx,
		"docker",
		append(
			[]string{"run"},
			args...,
		)...,
	)
	cmd.Cancel = func() error {
		// docker forwards this to the container, which lets it (and --rm) shut down cleanly
		return cmd.Process.Signal(os.Interrupt)
	}
	cmd.WaitDelay = 10 * time.Second

	return cmd
}

// seedTestDB installs a locally built vulnerability DB into a new directory and returns that
// directory, so that tests can run grype without downloading the real DB.
func seedTestDB(t *testing.T) string {
	t.Helper()

	dbDir := t.TempDir()
	cmd, stdout, stderr := runGrype(t, map[string]string{
		"GRYPE_DB_CACHE_DIR":  dbDir,
		"GRYPE_DB_UPDATE_URL": dbtest.NewServer(t).Start(),
	}, "db", "update", "-v")
	assertSucceedingReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())

	return dbDir
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
