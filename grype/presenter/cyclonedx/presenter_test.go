package cyclonedx

import (
	"bytes"
	"flag"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")
var validatorImage = "cyclonedx/cyclonedx-cli:0.27.2@sha256:829c9ea8f2104698bc3c1228575bfa495f6cc4ec151329323c013ca94408477f"

func Test_CycloneDX_Valid(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	tests := []struct {
		name   string
		scheme internal.SyftSource
	}{
		{
			name:   "json directory",
			scheme: internal.DirectorySource,
		},
		{
			name:   "json image",
			scheme: internal.ImageSource,
		},
		{
			name:   "xml directory",
			scheme: internal.DirectorySource,
		},
		{
			name:   "xml image",
			scheme: internal.ImageSource,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			format := strings.Split(tc.name, " ")[0]
			var buffer bytes.Buffer

			pb := internal.GeneratePresenterConfig(t, tc.scheme)

			var pres *Presenter
			switch format {
			case "json":
				pres = NewJSONPresenter(pb)
			case "xml":
				pres = NewXMLPresenter(pb)
			default:
				t.Fatalf("invalid format: %s", format)
			}

			err := pres.Present(&buffer)
			require.NoError(t, err)

			contents := buffer.String()

			cmd := exec.Command("docker", "run", "--rm", "-i", "--entrypoint", "/bin/sh", validatorImage,
				"-c", fmt.Sprintf("tee &> /dev/null && cyclonedx validate --input-version v1_6 --fail-on-errors --input-format %s", format))

			out := bytes.Buffer{}
			cmd.Stdout = &out
			cmd.Stderr = &out

			// pipe to the docker command
			cmd.Stdin = strings.NewReader(contents)

			err = cmd.Run()
			if err != nil || cmd.ProcessState.ExitCode() != 0 {
				// not valid
				t.Fatalf("error validating CycloneDX %s document: %s \nBOM:\n%s", format, out.String(), contents)
			}
		})
	}
}

func Test_noTypedNils(t *testing.T) {
	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			FileMetadata: map[file.Coordinates]file.Metadata{},
			FileDigests:  map[file.Coordinates][]file.Digest{},
		},
	}
	c := file.NewCoordinates("/file", "123")
	s.Artifacts.FileMetadata[c] = file.Metadata{
		Path: "/file",
	}
	s.Artifacts.FileDigests[c] = []file.Digest{}

	p := NewJSONPresenter(models.PresenterConfig{
		SBOM:   &s,
		Pretty: false,
	})
	contents := bytes.Buffer{}
	err := p.Present(&contents)
	require.NoError(t, err)
	require.NotContains(t, contents.String(), "null")
}

func TestCycloneDxPresenterImage(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	pres := NewJSONPresenter(pb)
	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which are tested independently
	actual = internal.Redact(actual)
	expected = internal.Redact(expected)

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}
}

func TestCycloneDxPresenterDir(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.DirectorySource)

	pres := NewJSONPresenter(pb)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which are tested independently
	actual = internal.Redact(actual)
	expected = internal.Redact(expected)

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}
}
