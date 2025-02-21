package pkg

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const cpeInputPrefix = "cpe:"

type CPELiteralMetadata struct {
	CPE string
}

func cpeProvider(userInput string) ([]Package, Context, *sbom.SBOM, error) {
	reader, ctx, err := getCPEReader(userInput)
	if err != nil {
		return nil, Context{}, nil, err
	}

	return decodeCPEsFromReader(reader, ctx)
}

func getCPEReader(userInput string) (r io.Reader, ctx Context, err error) {
	if strings.HasPrefix(userInput, cpeInputPrefix) {
		ctx.Source = &source.Description{
			Metadata: CPELiteralMetadata{
				CPE: userInput,
			},
		}
		return strings.NewReader(userInput), ctx, nil
	}
	return nil, ctx, errDoesNotProvide
}

func decodeCPEsFromReader(reader io.Reader, ctx Context) ([]Package, Context, *sbom.SBOM, error) {
	scanner := bufio.NewScanner(reader)
	var packages []Package
	var syftPkgs []pkg.Package

	for scanner.Scan() {
		rawLine := scanner.Text()
		p, syftPkg, err := cpeToPackage(rawLine)
		if err != nil {
			return nil, Context{}, nil, err
		}

		if p != nil {
			packages = append(packages, *p)
		}
		if syftPkg != nil {
			syftPkgs = append(syftPkgs, *syftPkg)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, Context{}, nil, err
	}

	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(syftPkgs...),
		},
	}

	return packages, ctx, s, nil
}

func cpeToPackage(rawLine string) (*Package, *pkg.Package, error) {
	c, err := cpe.New(rawLine, "")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode cpe %q: %w", rawLine, err)
	}

	syftPkg := pkg.Package{
		Name:    c.Attributes.Product,
		Version: c.Attributes.Version,
		CPEs:    []cpe.CPE{c},
		// TODO infer from cpe target sw, this is not as important since the only matcher for CPEs is the stock matcher
		//Type:     pkgType,
		// Language:...
	}

	syftPkg.SetID()

	return &Package{
		ID:       ID(c.Attributes.BindToFmtString()),
		CPEs:     syftPkg.CPEs,
		Name:     syftPkg.Name,
		Version:  syftPkg.Version,
		Type:     syftPkg.Type,
		Language: syftPkg.Language,
	}, &syftPkg, nil
}
