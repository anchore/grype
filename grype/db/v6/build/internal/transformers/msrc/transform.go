package msrc

import (
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

func Transform(vulnerability unmarshal.MSRCVulnerability, state provider.State) ([]data.Entry, error) {
	ins := []any{
		getVulnerability(vulnerability, state),
	}

	ins = append(ins, getAffectedPackage(vulnerability))

	return transformers.NewEntries(ins...), nil
}

func getVulnerability(vuln unmarshal.MSRCVulnerability, state provider.State) db.VulnerabilityHandle {
	return db.VulnerabilityHandle{
		Name:       vuln.ID,
		ProviderID: state.Provider,
		Provider:   internal.ProviderModel(state),
		Status:     db.VulnerabilityActive,
		BlobValue: &db.VulnerabilityBlob{
			ID:          vuln.ID,
			Description: strings.TrimSpace(vuln.Summary),
			References:  getReferences(vuln),
			Severities:  getSeverities(vuln),
		},
	}
}

func getAffectedPackage(vuln unmarshal.MSRCVulnerability) db.AffectedPackageHandle {
	return db.AffectedPackageHandle{
		Package: getPackage(vuln),
		BlobValue: &db.PackageBlob{
			Ranges: getRanges(vuln),
		},
	}
}

func getPackage(vuln unmarshal.MSRCVulnerability) *db.Package {
	return &db.Package{
		Name:      name.Normalize(vuln.Product.ID, pkg.KbPkg),
		Ecosystem: string(pkg.KbPkg),
	}
}

func getRanges(vuln unmarshal.MSRCVulnerability) []db.Range {
	// In anchore-enterprise windows analyzer, "base" represents unpatched windows images (images with no KBs)
	// If a vulnerability exists for a Microsoft Product ID and the image has no KBs (which are patches),
	// then the image must be vulnerable to the image.
	vuln.Vulnerable = append(vuln.Vulnerable, "base")

	return []db.Range{
		{
			Version: db.Version{
				Type:       "kb",
				Constraint: versionutil.OrConstraints(vuln.Vulnerable...),
			},
			Fix: getFix(vuln),
		},
	}
}

func getFix(vuln unmarshal.MSRCVulnerability) *db.Fix {
	fixedInVersion, fixDetail := fixedInKB(vuln)

	fixState := db.FixedStatus
	if fixedInVersion == "" {
		fixState = db.NotFixedStatus
	}

	return &db.Fix{
		Version: fixedInVersion,
		State:   fixState,
		Detail:  fixDetail,
	}
}

// fixedInKB finds the "latest" patch (KB id) amongst the available microsoft patches and returns it
// if the "latest" patch cannot be found, an empty string is returned
func fixedInKB(vulnerability unmarshal.MSRCVulnerability) (string, *db.FixDetail) {
	for _, fixedIn := range vulnerability.FixedIn {
		if fixedIn.IsLatest {
			var detail *db.FixDetail
			if fixedIn.Available.Date != "" {
				detail = &db.FixDetail{
					Available: &db.FixAvailability{
						Date: internal.ParseTime(fixedIn.Available.Date),
						Kind: fixedIn.Available.Kind,
					},
				}
			}
			return fixedIn.ID, detail
		}
	}
	return "", nil
}

func getReferences(vuln unmarshal.MSRCVulnerability) []db.Reference {
	refs := []db.Reference{
		{
			URL: vuln.Link,
		},
	}

	return refs
}

func getSeverities(vuln unmarshal.MSRCVulnerability) []db.Severity {
	var severities []db.Severity

	cleanSeverity := strings.ToLower(strings.TrimSpace(vuln.Severity))
	if cleanSeverity != "" {
		severities = append(severities, db.Severity{
			Scheme: db.SeveritySchemeCHML,
			Value:  cleanSeverity,
		})
	}

	if vuln.Cvss.Vector != "" {
		severities = append(severities, db.Severity{
			Scheme: db.SeveritySchemeCVSS,
			Value: db.CVSSSeverity{
				Vector:  vuln.Cvss.Vector,
				Version: "3.0", // TODO: assuming CVSS v3, update if different
			},
		})
	}

	return severities
}
