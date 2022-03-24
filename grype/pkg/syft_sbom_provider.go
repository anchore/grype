package pkg

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft"
)

type errEmptySBOM struct {
	sbomFilepath string
}

func (e errEmptySBOM) Error() string {
	return fmt.Sprintf("SBOM file is empty: %s", e.sbomFilepath)
}

func syftSBOMProvider(userInput string, config ProviderConfig) ([]Package, Context, error) {
	reader, err := getSBOMReader(userInput)
	if err != nil {
		return nil, Context{}, err
	}

	sbom, format, err := syft.Decode(reader)
	if err != nil {
		return nil, Context{}, fmt.Errorf("unable to decode sbom: %w", err)
	}
	if format == nil {
		return nil, Context{}, errDoesNotProvide
	}

	return FromCatalog(sbom.Artifacts.PackageCatalog, config), Context{
		Source: &sbom.Source,
		Distro: sbom.Artifacts.LinuxDistribution,
	}, nil
}

func getSBOMReader(userInput string) (io.Reader, error) {
	if userInput == "" {
		// we only want to attempt reading in from stdin if the user has not specified other
		// options from the CLI, otherwise we should not assume there is any valid input from stdin.
		return stdinReader(), nil
	}

	if explicitlySpecifyingSBOM(userInput) {
		filepath := strings.TrimPrefix(userInput, "sbom:")

		sbom, err := openSbom(filepath)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified SBOM: %w", err)
		}

		if !sbomHasContent(sbom) {
			return nil, errEmptySBOM{filepath}
		}

		return sbom, nil
	}

	// as a last resort, see if the raw user input specified an SBOM file
	if isPossibleSBOM(userInput) {
		sbom, err := openSbom(userInput)
		if err == nil {
			return sbom, nil
		}
	}

	// no usable SBOM is available
	return nil, errDoesNotProvide
}

// sbomHasContent returns a bool indicating whether the given SBOM file has data that could possibly be utilized in
// downstream processing.
func sbomHasContent(sbom *os.File) bool {
	if sbom == nil {
		return false
	}

	info, err := sbom.Stat()
	if err != nil {
		return false
	}

	if size := info.Size(); size > 0 {
		return true
	}

	return false
}

func stdinReader() io.Reader {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return nil
	}

	if !isPipedInput {
		return nil
	}

	return os.Stdin
}

func openSbom(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	sbom, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM: %w", err)
	}

	return sbom, nil
}

func isPossibleSBOM(userInput string) bool {
	f, err := os.Open(userInput)
	if err != nil {
		return false
	}
	mType, err := mimetype.DetectReader(f)
	if err != nil {
		return false
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		log.Warnf("unable to seek to the start of the possible SBOM file=%q: %w", userInput, err)
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
