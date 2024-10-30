package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

func syftSBOMProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	s, err := getSBOM(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	catalog := removePackagesByOverlap(s.Artifacts.Packages, s.Relationships, s.Artifacts.LinuxDistribution)

	return FromCollection(catalog, config.SynthesisConfig), Context{
		Source: &s.Source,
		Distro: s.Artifacts.LinuxDistribution,
	}, s, nil
}

func newInputInfo(scheme, contentTye string) *inputInfo {
	return &inputInfo{
		Scheme:      scheme,
		ContentType: contentTye,
	}
}

type inputInfo struct {
	ContentType string
	Scheme      string
}

func getSBOM(userInput string) (*sbom.SBOM, error) {
	reader, err := getSBOMReader(userInput)
	if err != nil {
		return nil, err
	}

	s, fmtID, _, err := format.Decode(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode sbom: %w", err)
	}

	if fmtID == "" || s == nil {
		return nil, errDoesNotProvide
	}

	return s, nil
}

func getSBOMReader(userInput string) (r io.ReadSeeker, err error) {
	r, _, err = extractReaderAndInfo(userInput)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func extractReaderAndInfo(userInput string) (io.ReadSeeker, *inputInfo, error) {
	switch {
	// the order of cases matter
	case userInput == "":
		// we only want to attempt reading in from stdin if the user has not specified other
		// options from the CLI, otherwise we should not assume there is any valid input from stdin.
		r, err := stdinReader()
		if err != nil {
			return nil, nil, err
		}
		return decodeStdin(r)

	case explicitlySpecifyingSBOM(userInput):
		filepath := strings.TrimPrefix(userInput, "sbom:")
		return parseSBOM("sbom", filepath)

	case isPossibleSBOM(userInput):
		return parseSBOM("", userInput)

	default:
		return nil, nil, errDoesNotProvide
	}
}

func parseSBOM(scheme, path string) (io.ReadSeeker, *inputInfo, error) {
	r, err := openFile(path)
	if err != nil {
		return nil, nil, err
	}
	info := newInputInfo(scheme, "sbom")
	return r, info, nil
}

func decodeStdin(r io.Reader) (io.ReadSeeker, *inputInfo, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading stdin: %w", err)
	}

	reader := bytes.NewReader(b)
	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse stdin: %w", err)
	}

	return reader, newInputInfo("", "sbom"), nil
}

func stdinReader() (io.Reader, error) {
	isStdinPipeOrRedirect, err := internal.IsStdinPipeOrRedirect()
	if err != nil {
		return nil, fmt.Errorf("unable to determine if there is piped input: %w", err)
	}

	if !isStdinPipeOrRedirect {
		return nil, errors.New("no input was provided via stdin")
	}

	return os.Stdin, nil
}

func closeFile(f *os.File) {
	if f == nil {
		return
	}

	err := f.Close()
	if err != nil {
		log.Warnf("failed to close file %s: %v", f.Name(), err)
	}
}

func openFile(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	f, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", expandedPath, err)
	}

	return f, nil
}

func isPossibleSBOM(userInput string) bool {
	f, err := openFile(userInput)
	if err != nil {
		return false
	}
	defer closeFile(f)

	mType, err := mimetype.DetectReader(f)
	if err != nil {
		return false
	}

	// we expect application/json, application/xml, and text/plain input documents. All of these are either
	// text/plain or a descendant of text/plain. Anything else cannot be an input SBOM document.
	return isAncestorOfMimetype(mType, "text/plain")
}

func isAncestorOfMimetype(mType *mimetype.MIME, expected string) bool {
	for cur := mType; cur != nil; cur = cur.Parent() {
		if cur.Is(expected) {
			return true
		}
	}
	return false
}

func explicitlySpecifyingSBOM(userInput string) bool {
	return strings.HasPrefix(userInput, "sbom:")
}
