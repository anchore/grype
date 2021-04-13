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

	"github.com/acarl005/stripansi"
)

type traitAssertion func(tb testing.TB, stdout, stderr string, rc int)

func assertInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		if !strings.Contains(stripansi.Strip(stderr), data) && !strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("data=%q was NOT found in any output, but should have been there", data)
		}
	}
}

func getGrypeCommand(t testing.TB, args ...string) *exec.Cmd {
	var binaryLocation string
	if os.Getenv("GRYPE_BINARY_LOCATION") != "" {
		// GRYPE_BINARY_LOCATION is the absolute path to the snapshot binary
		binaryLocation = os.Getenv("GRYPE_BINARY_LOCATION")
	} else {
		// note: there is a subtle - vs _ difference between these versions
		switch runtime.GOOS {
		case "darwin":
			binaryLocation = path.Join(repoRoot(t), fmt.Sprintf("snapshot/grype-macos_darwin_%s/grype", runtime.GOARCH))
		case "linux":
			binaryLocation = path.Join(repoRoot(t), fmt.Sprintf("snapshot/grype_linux_%s/grype", runtime.GOARCH))
		default:
			t.Fatalf("unsupported OS: %s", runtime.GOOS)
		}

	}
	cmd := exec.Command(binaryLocation, args...)
	// note: we need to preserve env vars + add an additional var to suppress checking for app updates
	cmd.Env = append(os.Environ(), "GRYPE_CHECK_FOR_APP_UPDATE=false")
	return cmd
}

func runGrypeCommand(t testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	cmd := getGrypeCommand(t, args...)
	if env != nil {
		cmd.Env = append(cmd.Env, envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	cmd.Run()

	return cmd, stdout.String(), stderr.String()
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

func repoRoot(t testing.TB) string {
	t.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		t.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}

func attachFileToCommandStdin(t testing.TB, file io.Reader, command *exec.Cmd) {
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.Copy(stdin, file)
	if err != nil {
		t.Fatal(err)
	}
	err = stdin.Close()
	if err != nil {
		t.Fatal(err)
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
