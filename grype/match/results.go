package match

import (
	"fmt"
	"slices"
	"sort"
	"strings"

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

func (p PackageParameter) compare(other PackageParameter) int {
	if c := strings.Compare(p.Name, other.Name); c != 0 {
		return c
	}
	return strings.Compare(p.Version, other.Version)
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

// compare orders two CPE search parameters, most significant field first.
func (i CPEParameters) compare(other CPEParameters) int {
	if c := strings.Compare(i.Namespace, other.Namespace); c != 0 {
		return c
	}
	if c := i.Package.compare(other.Package); c != 0 {
		return c
	}
	return slices.Compare(i.CPEs, other.CPEs)
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

func (h CPEResult) compare(other CPEResult) int {
	if c := strings.Compare(h.VulnerabilityID, other.VulnerabilityID); c != 0 {
		return c
	}
	if c := strings.Compare(h.VersionConstraint, other.VersionConstraint); c != 0 {
		return c
	}
	return slices.Compare(h.CPEs, other.CPEs)
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

func (d DistroParameters) compare(other DistroParameters) int {
	if c := strings.Compare(d.Namespace, other.Namespace); c != 0 {
		return c
	}
	if c := strings.Compare(d.Distro.Type, other.Distro.Type); c != 0 {
		return c
	}
	if c := strings.Compare(d.Distro.Version, other.Distro.Version); c != 0 {
		return c
	}
	return d.Package.compare(other.Package)
}

type DistroResult struct {
	VulnerabilityID   string `json:"vulnerabilityID"`
	VersionConstraint string `json:"versionConstraint"`
}

func (d DistroResult) Equals(other DistroResult) bool {
	return d.VulnerabilityID == other.VulnerabilityID &&
		d.VersionConstraint == other.VersionConstraint
}

func (d DistroResult) compare(other DistroResult) int {
	if c := strings.Compare(d.VulnerabilityID, other.VulnerabilityID); c != 0 {
		return c
	}
	return strings.Compare(d.VersionConstraint, other.VersionConstraint)
}

type EcosystemParameters struct {
	Language  string           `json:"language"`
	Namespace string           `json:"namespace"`
	Package   PackageParameter `json:"package"`
}

func (e *EcosystemParameters) Merge(other EcosystemParameters) error {
	if e.Namespace != other.Namespace {
		return fmt.Errorf("namespaces do not match")
	}
	if e.Language != other.Language {
		return fmt.Errorf("languages do not match")
	}
	if e.Package.Name != other.Package.Name {
		return fmt.Errorf("package names do not match")
	}
	if e.Package.Version != other.Package.Version {
		return fmt.Errorf("package versions do not match")
	}
	return nil
}

func (e EcosystemParameters) compare(other EcosystemParameters) int {
	if c := strings.Compare(e.Namespace, other.Namespace); c != 0 {
		return c
	}
	if c := strings.Compare(e.Language, other.Language); c != 0 {
		return c
	}
	return e.Package.compare(other.Package)
}

type EcosystemResult struct {
	VulnerabilityID   string `json:"vulnerabilityID"`
	VersionConstraint string `json:"versionConstraint"`
	// MatchedSymbols is the sorted, de-duplicated set of vulnerable Go symbols the package was found to
	// use, empty unless the match was scoped by symbol evidence.
	MatchedSymbols []string `json:"matchedSymbols,omitempty"`
}

func (e EcosystemResult) compare(other EcosystemResult) int {
	if c := strings.Compare(e.VulnerabilityID, other.VulnerabilityID); c != 0 {
		return c
	}
	if c := strings.Compare(e.VersionConstraint, other.VersionConstraint); c != 0 {
		return c
	}
	return slices.Compare(e.MatchedSymbols, other.MatchedSymbols)
}
