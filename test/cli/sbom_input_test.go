package cli

import (
	"os"
	"os/exec"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

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
			"absolute path - image scan",
			path.Join(workingDirectory, "./test-fixtures/sbom-ubuntu-20.04--pruned.json"),
		},
		{
			"relative path - image scan",
			"./test-fixtures/sbom-ubuntu-20.04--pruned.json",
		},
		{
			"directory scan",
			"./test-fixtures/sbom-grype-source.json",
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
	tests := []struct {
		name       string
		input      string
		args       []string
		wantErr    require.ErrorAssertionFunc
		wantOutput string
	}{
		{
			name:       "empty file",
			input:      "./test-fixtures/empty.json",
			args:       []string{"-c", "../grype-test-config.yaml"},
			wantErr:    require.Error,
			wantOutput: "unable to decode sbom: sbom format not recognized",
		},
		{
			name:    "sbom",
			input:   "./test-fixtures/sbom-ubuntu-20.04--pruned.json",
			args:    []string{"-c", "../grype-test-config.yaml"},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(getGrypeSnapshotLocation(t, runtime.GOOS), tt.args...)

			input, err := os.Open(tt.input)
			require.NoError(t, err)

			attachFileToCommandStdin(t, input, cmd)
			err = input.Close()
			require.NoError(t, err)

			output, err := cmd.CombinedOutput()
			tt.wantErr(t, err, "output: %s", output)
			if tt.wantOutput != "" {
				require.Contains(t, string(output), tt.wantOutput)
			}

		})
	}
}
