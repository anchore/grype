package options

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/name"
	grypePkg "github.com/anchore/grype/grype/pkg"
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

			// decode the PURL into a package via the same provider path scanning uses, then ask
			// the name resolver for the DB search names. This keeps namespaced ecosystems (golang
			// module paths, npm scopes, Maven group:artifact) in sync with how records are stored
			// instead of reimplementing the reconstruction here.
			if err := o.appendPURLSpecs(p, purl.Type); err != nil {
				return err
			}

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

// appendPURLSpecs decodes a package URL string into one or more packages and adds a
// package and CPE specifier for each search name the DB name resolver reports. Decoding
// through the provider (the same path used during a scan) means namespaced ecosystems keep
// their full stored name: a golang module PURL resolves to the whole module path, an npm
// scoped PURL keeps its scope, and Maven resolves to group:artifact. The name resolver also
// applies ecosystem-specific normalization (for example PEP 503 for Python), so search and
// the data side stay in agreement without this command reimplementing that logic.
//
// fallbackEcosystem is the PURL type; it is used when a decoded package carries no type so an
// otherwise-valid PURL still searches within its ecosystem.
func (o *DBSearchPackages) appendPURLSpecs(purlStr, fallbackEcosystem string) error {
	pkgs, _, _, err := grypePkg.Provide(purlStr, grypePkg.ProviderConfig{})
	if err != nil {
		return fmt.Errorf("unable to resolve package URL from %q: %w", purlStr, err)
	}

	for i := range pkgs {
		p := pkgs[i]
		ecosystem := string(p.Type)
		if ecosystem == "" {
			ecosystem = fallbackEcosystem
		}
		for _, n := range name.PackageNames(p) {
			o.PkgSpecs = append(o.PkgSpecs, &v6.PackageSpecifier{Name: n, Ecosystem: ecosystem})
			o.CPESpecs = append(o.CPESpecs, &v6.PackageSpecifier{CPE: &cpe.Attributes{Part: "a", Product: n, TargetSW: ecosystem}})
		}
	}

	return nil
}
