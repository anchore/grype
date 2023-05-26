package pkg

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

const (
	purlInputPrefix  = "purl:"
	cpesQualifierKey = "cpes"
)

type errEmptyPurlFile struct {
	purlFilepath string
}

func (e errEmptyPurlFile) Error() string {
	return fmt.Sprintf("purl file is empty: %s", e.purlFilepath)
}

func purlProvider(userInput string) ([]Package, Context, error) {
	p, err := getPurlPackages(userInput)
	return p, Context{}, err
}

func getPurlPackages(userInput string) ([]Package, error) {
	reader, err := getPurlReader(userInput)
	if err != nil {
		return nil, err
	}

	return decodePurlFile(reader)
}

func decodePurlFile(reader io.Reader) ([]Package, error) {
	scanner := bufio.NewScanner(reader)
	packages := []Package{}

	for scanner.Scan() {
		rawLine := scanner.Text()
		purl, err := packageurl.FromString(rawLine)
		if err != nil {
			return nil, fmt.Errorf("unable to decode purl %s: %w", rawLine, err)
		}

		cpes := []wfn.Attributes{}
		epoch := "0"
		for _, qualifier := range purl.Qualifiers {
			if qualifier.Key == cpesQualifierKey {
				rawCpes := strings.Split(qualifier.Value, ",")
				for _, rawCpe := range rawCpes {
					c, err := cpe.New(rawCpe)
					if err != nil {
						return nil, fmt.Errorf("unable to decode cpe %s in purl %s: %w", rawCpe, rawLine, err)
					}
					cpes = append(cpes, c)
				}
			}

			if qualifier.Key == "epoch" {
				epoch = qualifier.Value
			}
		}

		if purl.Type == packageurl.TypeRPM && !strings.HasPrefix(purl.Version, fmt.Sprintf("%s:", epoch)) {
			purl.Version = fmt.Sprintf("%s:%s", epoch, purl.Version)
		}

		packages = append(packages, Package{
			ID:       ID(purl.String()),
			CPEs:     cpes,
			Name:     purl.Name,
			Version:  purl.Version,
			Type:     pkg.TypeByName(purl.Type),
			Language: pkg.LanguageByName(purl.Type),
			PURL:     purl.String(),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return packages, nil
}

func getPurlReader(userInput string) (r io.Reader, err error) {
	if !explicitlySpecifyingPurl(userInput) {
		return nil, errDoesNotProvide
	}

	path := strings.TrimPrefix(userInput, purlInputPrefix)

	return openPurlFile(path)
}

func openPurlFile(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open purls: %w", err)
	}

	f, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", expandedPath, err)
	}

	if !fileHasContent(f) {
		return nil, errEmptyPurlFile{path}
	}

	return f, nil
}

func explicitlySpecifyingPurl(userInput string) bool {
	return strings.HasPrefix(userInput, purlInputPrefix)
}
