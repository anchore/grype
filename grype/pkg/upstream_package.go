package pkg

import (
	"strings"

	"github.com/scylladb/go-set/strset"

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
		if u.Version != "" {
			tmp.Version = u.Version
		}
		tmp.Upstreams = nil

		// for each cpe, replace pkg name with origin and add to set
		cpeStrings := strset.New()
		for _, c := range tmp.CPEs {
			if u.Version != "" {
				c.Attributes.Version = u.Version
			}

			// use BindToFmtString because we search against unescaped CPE strings
			updatedCPEString := strings.ReplaceAll(c.Attributes.BindToFmtString(), p.Name, u.Name)

			cpeStrings.Add(updatedCPEString)
		}

		// with each entry in set, convert string to CPE and update the new CPEs
		var updatedCPEs []cpe.CPE
		for _, cpeString := range cpeStrings.List() {
			updatedCPE, _ := cpe.New(cpeString, "")
			updatedCPEs = append(updatedCPEs, updatedCPE)
		}
		tmp.CPEs = updatedCPEs

		setSrcArchOnUpstream(&tmp)
		markApkUpstreamSearch(&tmp)

		pkgs = append(pkgs, tmp)
	}
	return pkgs
}

// markApkUpstreamSearch flags an apk upstream copy so qualifiers can tell it apart from a cataloged
// package. ApkMetadata is stored by value, so the flag never reaches the original package.
func markApkUpstreamSearch(upstream *Package) {
	if upstream == nil {
		return
	}
	if m, ok := upstream.Metadata.(ApkMetadata); ok {
		m.UpstreamSearch = true
		upstream.Metadata = m
	}
}

// IsUpstreamSearch reports whether p is a copy built by UpstreamPackages to search an upstream package's
// entries, rather than a cataloged package.
func IsUpstreamSearch(p Package) bool {
	m, ok := p.Metadata.(ApkMetadata)
	return ok && m.UpstreamSearch
}

func setSrcArchOnUpstream(upstream *Package) {
	if upstream == nil {
		return
	}
	// TODO: additional cases can be added here as their matching becomes dependent
	// on architecture.
	if r, ok := upstream.Metadata.(RpmMetadata); ok {
		r.Arch = "src"
		upstream.Metadata = r
	}
}
