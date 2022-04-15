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

func TestAttestationInput_AsArgument(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no scheme",
			args: []string{"./test-fixtures/alpine.att.json", "--key", "./test-fixtures/cosign.pub"},
		},
		{
			name: "with scheme",
			args: []string{"att:test-fixtures/alpine.att.json", "--key", "./test-fixtures/cosign.pub"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := getGrypeCommand(t, tt.args...)
			assertCommandExecutionSuccess(t, cmd)
		})
	}
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
			name:       "no schema and no key",
			input:      "./test-fixtures/alpine.att.json",
			args:       []string{"-c", "../grype-test-config.yaml"},
			wantErr:    require.Error,
			wantOutput: "--key parameter is required to validate attestations",
		},
		{
			name:  "cycloneDX format",
			input: "test-fixtures/alpine.cdx.att.json",
			args: []string{
				"-c", "../grype-test-config.yaml",
				"--key", "./test-fixtures/cosign.pub",
			},
			wantErr: require.NoError,
		},
		{
			name:  "broken key",
			input: "test-fixtures/alpine.att.json",
			args: []string{
				"-c", "../grype-test-config.yaml",
				"--key", "./test-fixtures/cosign_broken.pub",
			},
			wantErr:    require.Error,
			wantOutput: "failed to verify attestation signature: cannot decode public key",
		},
		{
			name:  "different but valid key",
			input: "test-fixtures/alpine.att.json",
			args: []string{
				"-c", "../grype-test-config.yaml",
				"--key", "./test-fixtures/another_cosign.pub",
			},
			wantErr:    require.Error,
			wantOutput: "failed to verify attestation signature: key and signature don't match",
		},
		{
			name:    "sbom with intoto mime string",
			input:   "./test-fixtures/sbom-with-intoto-string.json",
			args:    []string{"-c", "../grype-test-config.yaml"},
			wantErr: require.NoError,
		},
		{
			name:       "empty file",
			input:      "./test-fixtures/empty.json",
			args:       []string{"-c", "../grype-test-config.yaml"},
			wantErr:    require.Error,
			wantOutput: "unable to decode sbom: unable to identify format",
		},
		{
			name:    "sbom",
			input:   "./test-fixtures/sbom-ubuntu-20.04--pruned.json",
			args:    []string{"-c", "../grype-test-config.yaml"},
			wantErr: require.NoError,
		},
		{
			name:  "sbom with unused attestation key",
			input: "./test-fixtures/sbom-ubuntu-20.04--pruned.json",
			args: []string{
				"-c", "../grype-test-config.yaml",
				"--key", "./test-fixtures/cosign.pub"},
			wantErr: require.Error,
		},
		{
			name:  "attestation",
			input: "./test-fixtures/alpine.att.json",
			args: []string{
				"-c", "../grype-test-config.yaml",
				"--key", "./test-fixtures/cosign.pub"},
			wantErr: require.NoError,
		},
		{
			name:    "attestation without key validation",
			input:   "./test-fixtures/alpine.att.json",
			args:    []string{"-c", "../ignore-att-signature.yaml"},
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
