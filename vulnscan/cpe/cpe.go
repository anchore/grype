package cpe

import (
	"fmt"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/umisama/go-cpe"
)

// TODO: would be great to allow these to be overridden by user data/config
var targetSoftware = map[pkg.Language][]string{
	pkg.Java: {
		"java",
		"maven",
		"jenkins",
		"cloudbees_jenkins",
	},
	pkg.JavaScript: {
		"node.js",
	},
	pkg.Python: {
		"python",
	},
	pkg.Ruby: {
		"ruby",
		"rails",
	},
}


type CPE *cpe.Item

func New(cpeStr string) (CPE, error){
	return cpe.NewItemFromFormattedString(cpeStr)
}

// Generate Create a list of CPEs, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func Generate(p *pkg.Package) ([]CPE, error) {
	version := cpe.NewStringAttr(p.Version)
	targetSoftwares, _ := candidateTargetSoftwareAttrs(p)
	vendors, _ := candidateVendors(p)
	products, _ := candidateProducts(p)

	cpes := make([]CPE, len(products)*len(vendors)*len(targetSoftwares))
	idx := 0
	for _, p := range products {
		for _, v := range vendors {
			for _, ts := range targetSoftwares {
				candidateCpe := cpe.NewItem()
				if err := candidateCpe.SetProduct(p); err != nil {
					return nil, fmt.Errorf("unable to set product='%s': %w", p, err)
				}

				if err := candidateCpe.SetVendor(v); err != nil {
					return nil, fmt.Errorf("unable to set vendor='%s': %w", v, err)
				}

				if err := candidateCpe.SetVersion(version); err != nil {
					return nil, fmt.Errorf("unable to set version='%s': %w", version, err)
				}

				if err := candidateCpe.SetTargetSw(ts); err != nil {
					return nil, fmt.Errorf("unable to set targetSw='%s': %w", ts, err)
				}

				cpes[idx] = candidateCpe
				idx++
			}
		}
	}

	return cpes, nil
}

func candidateTargetSoftwareAttrs(p *pkg.Package) ([]cpe.StringAttr, error) {
	mappedNames := targetSoftware[p.Language]

	if mappedNames == nil {
		mappedNames = []string{}
	}

	attrs := make([]cpe.StringAttr, len(mappedNames)+1)
	for idx, o := range mappedNames {
		attrs[idx] = cpe.NewStringAttr(o)
	}
	// last element is the any match, present for all
	attrs[len(mappedNames)] = cpe.Any

	return attrs, nil
}

func candidateVendors(p *pkg.Package) ([]cpe.StringAttr, error) {
	return []cpe.StringAttr{cpe.NewStringAttr(p.Name)}, nil
}

func candidateProducts(p *pkg.Package) ([]cpe.StringAttr, error) {
	return []cpe.StringAttr{cpe.NewStringAttr(p.Name)}, nil
}
