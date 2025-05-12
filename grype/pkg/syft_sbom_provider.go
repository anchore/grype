package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gabriel-vasile/mimetype"

	"github.com/anchore/go-homedir"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

type SBOMFileMetadata struct {
	Path string
}

func syftSBOMProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	s, fmtID, path, err := getSBOM(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	src := s.Source
	if src.Metadata == nil && path != "" {
		src.Metadata = SBOMFileMetadata{
			Path: path,
		}
	}

	d := distro.FromRelease(s.Artifacts.LinuxDistribution)

	catalog := removePackagesByOverlap(s.Artifacts.Packages, s.Relationships, d)

	var enhancers []Enhancer
	if fmtID != syftjson.ID {
		enhancers = purlEnhancers
	}

	return FromCollection(catalog, config.SynthesisConfig, enhancers...), Context{
		Source: &src,
		Distro: d,
	}, s, nil
}

func getSBOM(userInput string) (*sbom.SBOM, sbom.FormatID, string, error) {
	reader, path, err := getSBOMReader(userInput)
	if err != nil {
		return nil, "", path, err
	}

	s, fmtID, err := readSBOM(reader)
	return s, fmtID, path, err
}

func readSBOM(reader io.ReadSeeker) (*sbom.SBOM, sbom.FormatID, error) {
	s, fmtID, _, err := format.Decode(reader)
	if err != nil {
		return nil, "", fmt.Errorf("unable to decode sbom: %w", err)
	}

	if fmtID == "" || s == nil {
		return nil, "", errDoesNotProvide
	}

	return s, fmtID, nil
}

func getSBOMReader(userInput string) (io.ReadSeeker, string, error) {
	switch {
	// the order of cases matter
	case userInput == "":
		// we only want to attempt reading in from stdin if the user has not specified other
		// options from the CLI, otherwise we should not assume there is any valid input from stdin.
		r, err := stdinReader()
		if err != nil {
			return nil, "", err
		}
		return decodeStdin(r)

	case explicitlySpecifyingPurlList(userInput):
		filepath := strings.TrimPrefix(userInput, purlInputPrefix)
		return openFile(filepath)

	case explicitlySpecifyingSBOM(userInput):
		filepath := strings.TrimPrefix(userInput, "sbom:")
		return openFile(filepath)

	case isPossibleSBOM(userInput):
		return openFile(userInput)

	default:
		return nil, "", errDoesNotProvide
	}
}

func decodeStdin(r io.Reader) (io.ReadSeeker, string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, "", fmt.Errorf("failed reading stdin: %w", err)
	}

	reader := bytes.NewReader(b)
	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse stdin: %w", err)
	}

	return reader, "", nil
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

func openFile(path string) (io.ReadSeekCloser, string, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, path, fmt.Errorf("unable to open SBOM: %w", err)
	}

	f, err := os.Open(expandedPath)
	if err != nil {
		return nil, path, fmt.Errorf("unable to open file %s: %w", expandedPath, err)
	}

	return f, path, nil
}

func isPossibleSBOM(userInput string) bool {
	f, path, err := openFile(userInput)
	if err != nil {
		return false
	}
	defer log.CloseAndLogError(f, path)

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

func explicitlySpecifyingPurlList(userInput string) bool {
	return strings.HasPrefix(userInput, purlInputPrefix)
}
