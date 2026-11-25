package pkg

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/internal/architecture"
	"github.com/anchore/syft/syft/cpe"
)

type UpstreamPackage struct {
	Name    string // the package name
	Version string // the version of the package
}

func UpstreamPackages(p Package) (pkgs []Package) {
	original := p
	for _, u := range p.Upstreams {
		tmp := original

		if u.Name == "" {
			continue
		}

		tmp.Name = u.Name

		// we always consider upstreams to be "source packages"
		tmp.Arch = architecture.ArchSource

		if u.Version != "" {
			tmp.Version = u.Version
		}
		tmp.Upstreams = nil

		// Edit vendor and product only when the field is exactly the package name.
		// Replacing that name inside the formatted CPE also rewrites other
		// fields, and a name like "c" breaks the "cpe:2.3:" prefix. The parse
		// error used to be ignored, which appended an empty CPE.
		seen := strset.New()
		var updatedCPEs []cpe.CPE
		for _, c := range tmp.CPEs {
			if u.Version != "" {
				c.Attributes.Version = u.Version
			}
			if c.Attributes.Product == p.Name {
				c.Attributes.Product = u.Name
			}
			if c.Attributes.Vendor == p.Name {
				c.Attributes.Vendor = u.Name
			}
			formatted := c.Attributes.BindToFmtString()
			if seen.Has(formatted) {
				continue
			}
			seen.Add(formatted)
			updatedCPEs = append(updatedCPEs, c)
		}
		tmp.CPEs = updatedCPEs

		pkgs = append(pkgs, tmp)
	}
	return pkgs
}
