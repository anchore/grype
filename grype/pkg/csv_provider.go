package pkg

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

type errEmptyCSV struct {
	csvFilepath string
}

func (e errEmptyCSV) Error() string {
	return fmt.Sprintf("CSV file is empty: %s", e.csvFilepath)
}

func csvProvider(userInput string) ([]Package, Context, error) {
	p, err := getCSVPackages(userInput)
	return p, Context{}, err
}

func getCSVPackages(userInput string) ([]Package, error) {
	reader, err := getCSVReader(userInput)
	if err != nil {
		return nil, err
	}

	by, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read csv: %w", err)
	}

	return decodeCSV(bytes.NewReader(by))
}

func decodeCSV(reader io.Reader) ([]Package, error) {
	csvReader := csv.NewReader(reader)
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("unable to parse csv: %w", err)
	}

	packages := []Package{}

	for _, row := range records {
		rawCpe := strings.TrimSpace(row[0])
		cpe, err := pkg.NewCPE(rawCpe)
		if err != nil {
			return nil, fmt.Errorf("unable to decode cpe: %v: %w", rawCpe, err)
		}

		var (
			purl        string
			pkgType     = pkg.UnknownPkg
			pkgLanguage pkg.Language
			pkgVersion  = cpe.Version
		)

		if len(row) > 1 {
			purl = strings.TrimSpace(row[1])
			pkgType = pkg.TypeFromPURL(purl)
			if pkgLanguage == pkg.UnknownLanguage {
				pkgLanguage = pkg.LanguageFromPURL(purl)
			}
			if pkgVersion == wfn.NA || pkgVersion == wfn.Any {
				p, err := packageurl.FromString(purl)
				if err == nil {
					pkgVersion = p.Version
				}
			}
		}

		switch {
		case pkgVersion == wfn.NA || pkgVersion == wfn.Any:
			log.Warnf("fixed version is required in either purl or cpe (cpe=%+v, purl=%+v)", cpe, purl)
		case pkgLanguage == pkg.UnknownLanguage:
			log.Warnf("include a purl increase to matching accuracy with languages (cpe=%+v, purl=%+v)", cpe, purl)
		}

		packages = append(packages, Package{
			CPEs:     []wfn.Attributes{cpe},
			Name:     cpe.Product,
			Version:  pkgVersion,
			Type:     pkgType,
			Language: pkgLanguage,
		})
	}

	return packages, nil
}

func getCSVReader(userInput string) (r io.Reader, err error) {
	if !explicitlySpecifyingCSV(userInput) {
		return nil, errDoesNotProvide
	}

	path := strings.TrimPrefix(userInput, "csv:")

	return openCSV(path)
}

func openCSV(path string) (*os.File, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open csv: %w", err)
	}

	f, err := os.Open(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", expandedPath, err)
	}

	if !fileHasContent(f) {
		return nil, errEmptyCSV{path}
	}

	return f, nil
}

func explicitlySpecifyingCSV(userInput string) bool {
	return strings.HasPrefix(userInput, "csv:")
}
