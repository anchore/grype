package options

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
)

type DBSearchPackages struct {
	AllowBroadCPEMatching bool                 `yaml:"allow-broad-cpe-matching" json:"allow-broad-cpe-matching" mapstructure:"allow-broad-cpe-matching"`
	Packages              []string             `yaml:"packages" json:"packages" mapstructure:"packages"`
	Ecosystem             string               `yaml:"ecosystem" json:"ecosystem" mapstructure:"ecosystem"`
	PkgSpecs              v6.PackageSpecifiers `yaml:"-" json:"-" mapstructure:"-"`
	CPESpecs              v6.PackageSpecifiers `yaml:"-" json:"-" mapstructure:"-"`
}

func (o *DBSearchPackages) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&o.Packages, "pkg", "", "package name/CPE/PURL to search for")
	flags.StringVarP(&o.Ecosystem, "ecosystem", "", "ecosystem of the package to search within")
	flags.BoolVarP(&o.AllowBroadCPEMatching, "broad-cpe-matching", "", "allow for specific package CPE attributes to match with '*' values on the vulnerability")
}

func (o *DBSearchPackages) PostLoad() error {
	// note: this may be called multiple times, so we need to reset the specs each time
	o.PkgSpecs = nil
	o.CPESpecs = nil

	for _, p := range o.Packages {
		switch {
		case strings.HasPrefix(p, "cpe:"):
			c, err := cpe.NewAttributes(p)
			if err != nil {
				return fmt.Errorf("invalid CPE from %q: %w", o.Packages, err)
			}

			if c.Version != "" || c.Update != "" {
				log.Warnf("ignoring version and update values for %q", p)
				c.Version = ""
				c.Update = ""
			}

			s := &v6.PackageSpecifier{CPE: &c}
			o.CPESpecs = append(o.CPESpecs, s)
			o.PkgSpecs = append(o.PkgSpecs, s)
		case strings.HasPrefix(p, "pkg:"):
			if o.Ecosystem != "" {
				return errors.New("cannot specify both package URL and ecosystem")
			}

			purl, err := packageurl.FromString(p)
			if err != nil {
				return fmt.Errorf("invalid package URL from %q: %w", o.Packages, err)
			}

			if purl.Version != "" || len(purl.Qualifiers) > 0 {
				log.Warnf("ignoring version and qualifiers for package URL %q", purl)
			}

			name := packageNameFromPURL(purl)
			o.PkgSpecs = append(o.PkgSpecs, &v6.PackageSpecifier{Name: name, Ecosystem: purl.Type})
			o.CPESpecs = append(o.CPESpecs, &v6.PackageSpecifier{CPE: &cpe.Attributes{Part: "a", Product: name, TargetSW: purl.Type}})

		default:
			o.PkgSpecs = append(o.PkgSpecs, &v6.PackageSpecifier{Name: p, Ecosystem: o.Ecosystem})
			o.CPESpecs = append(o.CPESpecs, &v6.PackageSpecifier{
				CPE: &cpe.Attributes{Part: "a", Product: p},
			})
		}
	}

	if len(o.Packages) == 0 {
		if o.Ecosystem != "" {
			o.PkgSpecs = append(o.PkgSpecs, &v6.PackageSpecifier{Ecosystem: o.Ecosystem})
			o.CPESpecs = append(o.CPESpecs, &v6.PackageSpecifier{CPE: &cpe.Attributes{TargetSW: o.Ecosystem}})
		}
	}

	return nil
}

// packageNameFromPURL reconstructs the package name in the form the grype DB
// stores it in for the package's ecosystem. Most ecosystems are flat-namespaced
// and use purl.Name directly. Namespaced ecosystems like golang (module paths,
// e.g. "github.com/gin-gonic/gin") and npm (scoped packages, e.g. "@scope/name")
// split the namespace out of the name during PURL parsing, so it must be
// rejoined to match how the DB stores these names. Maven (java) packages are
// stored as "groupId:artifactId" by the DB build pipeline.
func packageNameFromPURL(purl packageurl.PackageURL) string {
	if purl.Namespace == "" {
		return purl.Name
	}
	switch purl.Type {
	case packageurl.TypeMaven:
		return purl.Namespace + ":" + purl.Name
	case packageurl.TypeGolang, packageurl.TypeNPM:
		return purl.Namespace + "/" + purl.Name
	}
	return purl.Name
}
