package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"testing"
)

// GRYPE_BINARY_LOCATION is relative to the repository root. (e.g., "snapshot/grype_linux_amd64/grype")
// This value is transformed due to the CLI tests' need for a path relative to the test directory.
var grypeBinaryLocation = path.Join("..", "..", os.Getenv("GRYPE_BINARY_LOCATION"))

const sbomLocation = "./test-fixtures/sbom-ubuntu-20.04--pruned.json"

func TestSBOMInput_AsArgument(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
	}{
		{
			"absolute path",
			path.Join(workingDirectory, sbomLocation),
		},
		{
			"relative path",
			sbomLocation,
		},
	}

	t.Run("explicit", func(t *testing.T) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				sbomArg := "sbom:" + tc.path
				cmd := getGrypeCommand(t, sbomArg)

				assertCommandExecutionSuccess(t, cmd)
			})
		}
	})

	t.Run("implicit", func(t *testing.T) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				sbomArg := tc.path
				cmd := getGrypeCommand(t, sbomArg)

				assertCommandExecutionSuccess(t, cmd)
			})
		}
	})
}

func TestSBOMInput_FromStdin(t *testing.T) {
	cmd := getGrypeCommand(t)

	sbom, err := os.Open(sbomLocation)
	if err != nil {
		t.Fatal(err)
	}

	attachFileToCommandStdin(t, sbom, cmd)

	assertCommandExecutionSuccess(t, cmd)
}

func getGrypeCommand(t *testing.T, args ...string) *exec.Cmd {
	grype, err := getCommand(grypeBinaryLocation, args...)
	if err != nil {
		t.Fatal(err)
	}

	return grype
}

// —— below this line is generalizable across projects

func getCommand(relativePathToBinary string, args ...string) (*exec.Cmd, error) {
	_, err := os.Stat(relativePathToBinary)
	if err != nil {
		return nil, fmt.Errorf("unable to lookup binary path %q: %w", relativePathToBinary, err)
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	resolvedPathToBinary := path.Join(workingDirectory, relativePathToBinary)

	return exec.Command(resolvedPathToBinary, args...), nil
}

func attachFileToCommandStdin(t *testing.T, file io.Reader, command *exec.Cmd) {
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

func assertCommandExecutionSuccess(t *testing.T, cmd *exec.Cmd) {
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
