package pkg

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set/strset"
)

type UpstreamPackage struct {
	Name    string // the package name
	Version string // the version of the package
}

func UpstreamPackages(p Package) <-chan Package {
	ret := make(chan Package)
	go func() {
		defer close(ret)

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
			for _, cpe := range tmp.CPEs {
				if u.Version != "" {
					cpe.Version = u.Version
				}

				updatedCPEString := strings.ReplaceAll(cpe.BindToFmtString(), p.Name, u.Name)

				cpeStrings.Add(updatedCPEString)
			}

			// with each entry in set, convert string to CPE and update the new CPEs
			var updatedCPEs []pkg.CPE
			for _, cpeString := range cpeStrings.List() {
				updatedCPE, _ := pkg.NewCPE(cpeString)
				updatedCPEs = append(updatedCPEs, updatedCPE)
			}
			tmp.CPEs = updatedCPEs

			ret <- tmp
		}
	}()
	return ret
}
