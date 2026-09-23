package osv

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/codename"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/syft/syft/pkg"
)

const (
	// cleanStart is the canonical distro name, matching distro.CleanStart and
	// the operating_system_specifier_overrides rows in db/v6/data.go.
	cleanStart = "cleanstart"

	// cleanStartShort is the abbreviated spelling that also appears as an OSV
	// ecosystem in the CleanStart advisory feed. Both spellings denote the same
	// distro and normalize to cleanStart.
	cleanStartShort = "clnstrt"

	// cleanStartRolling marks CleanStart OS rows as rolling-release, matching
	// how the other apk rolling distros (chainguard, wolfi) are stored.
	cleanStartRolling = "rolling"
)

// cleanstartStrategy handles CleanStart Security Advisory (CLEANSTART) records.
// CleanStart OSV records describe affected version ranges for APK packages.
//
// CleanStart-specific decisions:
//   - Ecosystem is "CleanStart" or "clnstrt" (both spellings appear in the
//     feed), optionally suffixed with ":<version>"; package type is always APK
//     and OS metadata is extracted from the ecosystem string.
//   - CleanStart is a rolling distro — no version suffix means rolling.
//   - OSV ranges (introduced/fixed events) are converted directly to
//     AffectedPackageHandle records with "< fixVersion" constraints, matching
//     how Alpine and Wolfi vulnerability data is stored.
//   - ADVISORY-type references get their refID set to the record ID.
type cleanstartStrategy struct{}

func (cleanstartStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "CLEANSTART-")
}

func (cleanstartStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	// CleanStart carries its CVE/GHSA identifiers in `upstream` (added in OSV
	// 1.7) and leaves `aliases` and `related` empty. Without this merge every
	// record would land in the DB with no CVE linkage at all.
	aliases := cleanstartAliases(vuln)

	// Withdrawn advisories must not produce matches, and a majority of the
	// CleanStart feed is withdrawn, so getting this wrong is a large source of
	// false positives.
	//
	// Marking the record Rejected is not enough on its own. The
	// OnlyNonWithdrawnVulnerabilities filter that govulndb and github rely on is
	// only applied on the CPE and language matcher paths (see
	// matcher/internal/cpe.go and language.go); FindResultsByDistro searches on
	// ByPackageName + ByDistro + OnlyQualifiedPackages and never consults
	// status. CleanStart is a distro provider, so its rows go down that path.
	//
	// The affected-package rows are therefore dropped outright — with nothing to
	// find, the distro matcher cannot match. The vulnerability handle is still
	// emitted, carrying Rejected + WithdrawnDate, so the advisory stays visible
	// to `grype db search` and to anything that reads status directly.
	status := db.VulnerabilityActive
	var withdrawnDate *time.Time
	withdrawn := !vuln.Withdrawn.IsZero()
	if withdrawn {
		status = db.VulnerabilityRejected
		withdrawnDate = &vuln.Withdrawn
	}

	in := []any{
		db.VulnerabilityHandle{
			Name:          vuln.ID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        status,
			ModifiedDate:  &vuln.Modified,
			PublishedDate: &vuln.Published,
			WithdrawnDate: withdrawnDate,
			BlobValue: &db.VulnerabilityBlob{
				ID:          vuln.ID,
				Description: vuln.Details,
				References:  cleanstartReferences(vuln),
				Aliases:     aliases,
				Severities:  severities,
			},
		},
	}

	if !withdrawn {
		for _, aph := range cleanstartAffectedPackages(vuln) {
			in = append(in, aph)
		}
	}
	return transformers.NewEntries(in...), nil
}

// cleanstartAliases collects the vulnerability identifiers a CleanStart record
// points at. The feed puts them in `upstream` (added in OSV 1.7) and leaves
// `aliases` and `related` empty; all three are read so the strategy keeps
// working if the producer starts populating the conventional OSV fields.
//
// Returns a freshly allocated slice on every call: the result is stored on both
// the vulnerability blob and each package blob, and sharing a backing array
// between them would let one append clobber another.
//
// IDs are passed through verbatim. The feed emits some GHSA ids fully
// lower-cased ("ghsa-hr2v-4r36-88hr"), which will not match the canonical
// "GHSA-hr2v-4r36-88hr" form, but case-folding belongs at the producer: a
// blanket ToUpper here would corrupt the lower-case suffix that is part of a
// well-formed GHSA id.
func cleanstartAliases(vuln unmarshal.OSVVulnerability) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, group := range [][]string{vuln.Aliases, vuln.Upstream, vuln.Related} {
		for _, id := range group {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func cleanstartReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refID := ""
		if ref.Type == osvmodel.ReferenceAdvisory {
			refID = vuln.ID
		}
		refs = append(refs, db.Reference{
			ID:   refID,
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func cleanstartAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		aphs = append(aphs, db.AffectedPackageHandle{
			Package:         cleanstartPackage(affected.Package),
			OperatingSystem: cleanstartOSFromEcosystem(affected.Package.Ecosystem),
			BlobValue:       cleanstartAffectedBlob(vuln, affected),
		})
	}
	sort.Sort(internal.ByAffectedPackage(aphs))
	return aphs
}

func cleanstartAffectedBlob(vuln unmarshal.OSVVulnerability, affected osvmodel.Affected) *db.PackageBlob {
	var ranges []db.Range
	for _, r := range affected.Ranges {
		ranges = append(ranges, getGrypeRangesFromRange(r, cleanstartRangeType(r.Type))...)
	}
	return &db.PackageBlob{
		CVEs:   cleanstartAliases(vuln),
		Ranges: ranges,
	}
}

func cleanstartPackage(p osvmodel.Package) *db.Package {
	return &db.Package{
		Ecosystem: pkg.ApkPkg.String(),
		Name:      name.Normalize(p.Name, pkg.ApkPkg),
	}
}

func cleanstartRangeType(t osvmodel.RangeType) string {
	if t == osvmodel.RangeEcosystem {
		return pkg.ApkPkg.String()
	}
	return defaultRangeType(t)
}

// cleanstartOSFromEcosystem extracts OS metadata from a CleanStart ecosystem
// string. Both the "CleanStart" and "clnstrt" spellings appear in the advisory
// feed and normalize to the same distro.
//
// CleanStart is a rolling distro, so a bare ecosystem with no version suffix
// becomes a rolling OS row carrying Name, ReleaseID and LabelVersion — the same
// shape the other apk rolling distros use (see cgOperatingSystem), which is
// what lets the apk distro matcher resolve these rows through
// operating_system_specifier_overrides.
func cleanstartOSFromEcosystem(ecosystem string) *db.OperatingSystem {
	if ecosystem == "" {
		return nil
	}

	parts := strings.SplitN(ecosystem, ":", 2)
	switch strings.ToLower(parts[0]) {
	case cleanStart, cleanStartShort:
	default:
		return nil
	}

	if len(parts) < 2 || parts[1] == "" {
		return &db.OperatingSystem{
			Name:         cleanStart,
			ReleaseID:    cleanStart,
			LabelVersion: cleanStartRolling,
		}
	}

	osVersion := parts[1]
	versionFields := strings.Split(osVersion, ".")
	if len(versionFields) == 0 || versionFields[0] == "" {
		return nil
	}

	major := versionFields[0]
	if _, err := strconv.Atoi(major[0:1]); err != nil {
		return &db.OperatingSystem{
			Name:         cleanStart,
			ReleaseID:    cleanStart,
			LabelVersion: osVersion,
			Codename:     codename.LookupOS(cleanStart, "", ""),
		}
	}

	var minor string
	if len(versionFields) > 1 {
		minor = versionFields[1]
	}
	return &db.OperatingSystem{
		Name:         cleanStart,
		ReleaseID:    cleanStart,
		MajorVersion: major,
		MinorVersion: minor,
		Codename:     codename.LookupOS(cleanStart, major, minor),
	}
}
