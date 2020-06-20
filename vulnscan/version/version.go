package version

import (
	"fmt"
	"github.com/umisama/go-cpe"

	"github.com/anchore/imgbom/imgbom/pkg"
	deb "github.com/knqyf263/go-deb-version"
	hashiVer "github.com/knqyf263/go-version"
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

type Version struct {
	Raw    string
	Format Format
	rich   rich
}

type rich struct {
	semVer  *hashiVer.Version
	dpkgVer *deb.Version
	cpeVers  []*cpe.Item  // CPEs have additional fields, so allow array here for testing combinations of vendor and product tuples
}

func NewVersion(raw string, format Format) (*Version, error) {
	version := &Version{
		Raw:    raw,
		Format: format,
	}

	err := version.populate()
	if err != nil {
		return nil, err
	}

	return version, nil
}

func NewVersionFromPkg(p *pkg.Package) (*Version, error) {
	return NewVersion(p.Version, FormatFromPkgType(p.Type))
}

func (v *Version) populate() error {
	switch v.Format {
	case SemanticFormat:
		version, err := newSemanticVersion(v.Raw)
		v.rich.semVer = version
		return err
	case DpkgFormat:
		version, err := newDpkgVersion(v.Raw)
		v.rich.dpkgVer = version
		return err
	case Cpe23Format:
		version, err := cpe.NewItemFromFormattedString(v.Raw)
		v.rich.cpeVers = make([]*cpe.Item, 1)
		v.rich.cpeVers[0] = version
		return err
	}
	return fmt.Errorf("no rich version populated (format=%s)", v.Format)
}

func (v Version) String() string {
	return fmt.Sprintf("%s (%s)", v.Raw, v.Format)
}

// generateCpes Create a list of Items, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func generateCpes(p *pkg.Package) ([]*cpe.Item, error) {
	version := cpe.NewStringAttr(p.Version)
	targetSoftwares, _ := candidateTargetSoftwareAttrs(p)
	vendors, _ := candidateVendors(p)
	products, _ := candidateProducts(p)

	cpes := make([]*cpe.Item, len(products) * len(vendors) * len(targetSoftwares) + 1)
	idx := 0
	for _, p := range products {
		for _, v := range vendors {
			for _, ts := range targetSoftwares {
				candidateCpe := cpe.NewItem()
				candidateCpe.SetProduct(p)
				candidateCpe.SetVendor(v)
				candidateCpe.SetVersion(version)
				candidateCpe.SetTargetSw(ts)
				cpes[idx] = candidateCpe
			}
		}
	}

	return cpes, nil
}

// Generate the set of possible target software attributes for a CPE from the package info
func candidateTargetSoftwareAttrs(p *pkg.Package) ([]cpe.StringAttr, error) {
	mappedNames := targetSoftware[p.Language]

	if mappedNames == nil {
		mappedNames = []string{} // Empty array
	}

	attrs := make([]cpe.StringAttr, len(mappedNames) + 1)
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