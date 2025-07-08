package msrc

import (
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	v6 "github.com/anchore/grype/internal/db/v6"
	"github.com/anchore/grype/internal/db/v6/data/transformers"
	"github.com/anchore/grype/internal/db/v6/data/transformers/internal"
	"github.com/anchore/grype/internal/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

func Transform(vulnerability unmarshal.MSRCVulnerability, state provider.State) ([]data.Entry, error) {
	ins := []any{
		getVulnerability(vulnerability, state),
	}

	ins = append(ins, getAffectedPackage(vulnerability))

	return transformers.NewEntries(ins...), nil
}

func getVulnerability(vuln unmarshal.MSRCVulnerability, state provider.State) v6.VulnerabilityHandle {
	return v6.VulnerabilityHandle{
		Name:       vuln.ID,
		ProviderID: state.Provider,
		Provider:   internal.ProviderModel(state),
		Status:     v6.VulnerabilityActive,
		BlobValue: &v6.VulnerabilityBlob{
			ID:          vuln.ID,
			Description: strings.TrimSpace(vuln.Summary),
			References:  getReferences(vuln),
			Severities:  getSeverities(vuln),
		},
	}
}

func getAffectedPackage(vuln unmarshal.MSRCVulnerability) v6.AffectedPackageHandle {
	return v6.AffectedPackageHandle{
		Package: getPackage(vuln),
		BlobValue: &v6.AffectedPackageBlob{
			Ranges: getRanges(vuln),
		},
	}
}

func getPackage(vuln unmarshal.MSRCVulnerability) *v6.Package {
	return &v6.Package{
		Name:      name.Normalize(vuln.Product.ID, pkg.KbPkg),
		Ecosystem: string(pkg.KbPkg),
	}
}

func getRanges(vuln unmarshal.MSRCVulnerability) []v6.AffectedRange {
	// In anchore-enterprise windows analyzer, "base" represents unpatched windows images (images with no KBs)
	// If a vulnerability exists for a Microsoft Product ID and the image has no KBs (which are patches),
	// then the image must be vulnerable to the image.
	vuln.Vulnerable = append(vuln.Vulnerable, "base")

	return []v6.AffectedRange{
		{
			Version: v6.AffectedVersion{
				Type:       "kb",
				Constraint: internal.OrConstraints(vuln.Vulnerable...),
			},
			Fix: getFix(vuln),
		},
	}
}

func getFix(vuln unmarshal.MSRCVulnerability) *v6.Fix {
	fixedInVersion := fixedInKB(vuln)

	fixState := v6.FixedStatus
	if fixedInVersion == "" {
		fixState = v6.NotFixedStatus
	}

	return &v6.Fix{
		Version: fixedInVersion,
		State:   fixState,
	}
}

// fixedInKB finds the "latest" patch (KB id) amongst the available microsoft patches and returns it
// if the "latest" patch cannot be found, an empty string is returned
func fixedInKB(vulnerability unmarshal.MSRCVulnerability) string {
	for _, fixedIn := range vulnerability.FixedIn {
		if fixedIn.IsLatest {
			return fixedIn.ID
		}
	}
	return ""
}

func getReferences(vuln unmarshal.MSRCVulnerability) []v6.Reference {
	refs := []v6.Reference{
		{
			URL: vuln.Link,
		},
	}

	return refs
}

func getSeverities(vuln unmarshal.MSRCVulnerability) []v6.Severity {
	var severities []v6.Severity

	cleanSeverity := strings.ToLower(strings.TrimSpace(vuln.Severity))
	if cleanSeverity != "" {
		severities = append(severities, v6.Severity{
			Scheme: v6.SeveritySchemeCHML,
			Value:  cleanSeverity,
		})
	}

	if vuln.Cvss.Vector != "" {
		severities = append(severities, v6.Severity{
			Scheme: v6.SeveritySchemeCVSS,
			Value: v6.CVSSSeverity{
				Vector:  vuln.Cvss.Vector,
				Version: "3.0", // TODO: assuming CVSS v3, update if different
			},
		})
	}

	return severities
}
