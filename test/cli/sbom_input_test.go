package cli

import (
	"os"
	"path"
	"testing"
)

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
