package match

import (
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"
)

type CPEParameters struct {
	Namespace string           `json:"namespace"`
	CPEs      []string         `json:"cpes"`
	Package   PackageParameter `json:"package"`
}

type PackageParameter struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (i *CPEParameters) Merge(other CPEParameters) error {
	if i.Namespace != other.Namespace {
		return fmt.Errorf("namespaces do not match")
	}

	existingCPEs := strset.New(i.CPEs...)
	newCPEs := strset.New(other.CPEs...)
	mergedCPEs := strset.Union(existingCPEs, newCPEs).List()
	sort.Strings(mergedCPEs)
	i.CPEs = mergedCPEs
	return nil
}

type CPEResult struct {
	VulnerabilityID   string   `json:"vulnerabilityID"`
	VersionConstraint string   `json:"versionConstraint"`
	CPEs              []string `json:"cpes"`
}

func (h CPEResult) Equals(other CPEResult) bool {
	if h.VersionConstraint != other.VersionConstraint {
		return false
	}

	if len(h.CPEs) != len(other.CPEs) {
		return false
	}

	for i := range h.CPEs {
		if h.CPEs[i] != other.CPEs[i] {
			return false
		}
	}

	return true
}

type DistroParameters struct {
	Distro    DistroIdentification `json:"distro"`
	Package   PackageParameter     `json:"package"`
	Namespace string               `json:"namespace"`
}

type DistroIdentification struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

func (d *DistroParameters) Merge(other DistroParameters) error {
	if d.Namespace != other.Namespace {
		return fmt.Errorf("namespaces do not match")
	}
	if d.Distro.Type != other.Distro.Type {
		return fmt.Errorf("distro types do not match")
	}
	if d.Distro.Version != other.Distro.Version {
		return fmt.Errorf("distro versions do not match")
	}
	if d.Package.Name != other.Package.Name {
		return fmt.Errorf("package names do not match")
	}
	if d.Package.Version != other.Package.Version {
		return fmt.Errorf("package versions do not match")
	}
	return nil
}

type DistroResult struct {
	VulnerabilityID   string `json:"vulnerabilityID"`
	VersionConstraint string `json:"versionConstraint"`
}

func (d DistroResult) Equals(other DistroResult) bool {
	return d.VulnerabilityID == other.VulnerabilityID &&
		d.VersionConstraint == other.VersionConstraint
}
