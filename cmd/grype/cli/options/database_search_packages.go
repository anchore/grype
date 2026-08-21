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

			o.PkgSpecs = append(o.PkgSpecs, &v6.PackageSpecifier{Name: packageNameFromPURL(purl), Ecosystem: purl.Type})
			o.CPESpecs = append(o.CPESpecs, &v6.PackageSpecifier{CPE: &cpe.Attributes{Part: "a", Product: purl.Name, TargetSW: purl.Type}})

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

// packageNameFromPURL joins the PURL namespace back onto the name, in the form
// the DB stores names for that ecosystem. Go modules and npm scopes are stored
// as the full "namespace/name" path and Maven coordinates as
// "groupId:artifactId", so without this a search for
// "pkg:golang/github.com/gin-gonic/gin" looks up the bare name "gin" and never
// matches. The CPE specifier keeps the bare name, since CPE product attributes
// are not namespaced.
func packageNameFromPURL(purl packageurl.PackageURL) string {
	if purl.Namespace == "" {
		return purl.Name
	}

	if purl.Type == packageurl.TypeMaven {
		return purl.Namespace + ":" + purl.Name
	}

	return purl.Namespace + "/" + purl.Name
}
