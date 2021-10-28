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
)

func getFixtureImage(tb testing.TB, fixtureImageName string) string {
	tb.Helper()

	imagetest.GetFixtureImage(tb, "docker-archive", fixtureImageName)
	return imagetest.GetFixtureImageTarPath(tb, fixtureImageName)
}

func getGrypeCommand(tb testing.TB, args ...string) *exec.Cmd {
	tb.Helper()

	var binaryLocation string
	if os.Getenv("GRYPE_BINARY_LOCATION") != "" {
		// GRYPE_BINARY_LOCATION is the absolute path to the snapshot binary
		binaryLocation = os.Getenv("GRYPE_BINARY_LOCATION")
	} else {
		// note: there is a subtle - vs _ difference between these versions
		switch runtime.GOOS {
		case "darwin":
			binaryLocation = path.Join(repoRoot(tb), fmt.Sprintf("snapshot/grype-macos_darwin_%s/grype", runtime.GOARCH))
		case "linux":
			binaryLocation = path.Join(repoRoot(tb), fmt.Sprintf("snapshot/grype_linux_%s/grype", runtime.GOARCH))
		default:
			tb.Fatalf("unsupported OS: %s", runtime.GOOS)
		}

	}
	return exec.Command(
		binaryLocation,
		append(
			[]string{"-c", "../grype-test-config.yaml"},
			args...,
		)...,
	)
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

	stdin, err := command.StdinPipe()
	if err != nil {
		tb.Fatal(err)
	}

	_, err = io.Copy(stdin, file)
	if err != nil {
		tb.Fatal(err)
	}
	err = stdin.Close()
	if err != nil {
		tb.Fatal(err)
	}
}

func assertCommandExecutionSuccess(t testing.TB, cmd *exec.Cmd) {
	t.Logf("Running command: %q", cmd)
	output, err := cmd.CombinedOutput()

	t.Logf("Full command output:\n%s\n", output)

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
