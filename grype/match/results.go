package match

import (
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"
)

type PackageParameter struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CPEParameters struct {
	Namespace string           `json:"namespace"`
	CPEs      []string         `json:"cpes"`
	Package   PackageParameter `json:"package"`
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

type PURLParameters struct {
	Namespace string           `json:"namespace"`
	PURL      string           `json:"purl"`
	Package   PackageParameter `json:"package"`
}

type PURLResult struct {
	VulnerabilityID   string `json:"vulnerabilityID"`
	VersionConstraint string `json:"versionConstraint"`
	PURL              string `json:"purl"`
}

func (h PURLResult) Equals(other PURLResult) bool {
	if h.VersionConstraint != other.VersionConstraint {
		return false
	}

	if h.PURL != other.PURL {
		return false
	}

	return true
}
