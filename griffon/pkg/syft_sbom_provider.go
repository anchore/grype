package pkg

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/nextlinux/griffon/internal"
	"github.com/nextlinux/griffon/internal/log"
)

type errEmptySBOM struct {
	sbomFilepath string
}

func (e errEmptySBOM) Error() string {
	return fmt.Sprintf("SBOM file is empty: %s", e.sbomFilepath)
}

func syftSBOMProvider(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	s, err := getSBOM(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	catalog := s.Artifacts.Packages
	catalog = removePackagesByOverlap(catalog, s.Relationships)

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

	s, format, err := syft.Decode(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode sbom: %w", err)
	}

	if format == nil {
		return nil, errDoesNotProvide
	}

	return s, nil
}

func getSBOMReader(userInput string) (r io.Reader, err error) {
	r, _, err = extractReaderAndInfo(userInput)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func extractReaderAndInfo(userInput string) (io.Reader, *inputInfo, error) {
	switch {
	// the order of cases matter
	case userInput == "":
		// we only want to attempt reading in from stdin if the user has not specified other
		// options from the CLI, otherwise we should not assume there is any valid input from stdin.
		return decodeStdin(stdinReader())

	case explicitlySpecifyingSBOM(userInput):
		filepath := strings.TrimPrefix(userInput, "sbom:")
		return parseSBOM("sbom", filepath)

	case isPossibleSBOM(userInput):
		return parseSBOM("", userInput)

	default:
		return nil, nil, errDoesNotProvide
	}
}

func parseSBOM(scheme, path string) (io.Reader, *inputInfo, error) {
	r, err := openFile(path)
	if err != nil {
		return nil, nil, err
	}
	info := newInputInfo(scheme, "sbom")
	return r, info, nil
}

func decodeStdin(r io.Reader) (io.Reader, *inputInfo, error) {
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

// fileHasContent returns a bool indicating whether the given file has data that could possibly be utilized in
// downstream processing.
func fileHasContent(f *os.File) bool {
	if f == nil {
		return false
	}

	info, err := f.Stat()
	if err != nil {
		return false
	}

	if size := info.Size(); size > 0 {
		return true
	}

	return false
}

func stdinReader() io.Reader {
	isStdinPipeOrRedirect, err := internal.IsStdinPipeOrRedirect()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return nil
	}

	if !isStdinPipeOrRedirect {
		return nil
	}

	return os.Stdin
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

	if !fileHasContent(f) {
		return nil, errEmptySBOM{path}
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
