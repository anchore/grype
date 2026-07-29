package osv

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

const dhiEcosystemPrefix = "Docker Hardened Images:"

type dhiStrategy struct{}

func (dhiStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "DHI-")
}

func (dhiStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	affected, err := dhiAffectedPackages(vuln, dhiAliases(vuln))
	if err != nil {
		return nil, err
	}
	if len(affected) == 0 {
		return nil, nil
	}

	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	aliases := dhiAliases(vuln)
	status := db.VulnerabilityActive
	var withdrawnDate *time.Time
	if !vuln.Withdrawn.IsZero() {
		status = db.VulnerabilityRejected
		withdrawnDate = &vuln.Withdrawn
	}
	in := []any{db.VulnerabilityHandle{
		Name:          vuln.ID,
		Status:        status,
		PublishedDate: &vuln.Published,
		ModifiedDate:  &vuln.Modified,
		WithdrawnDate: withdrawnDate,
		ProviderID:    state.Provider,
		Provider:      provider.Model(state),
		BlobValue: &db.VulnerabilityBlob{
			ID:          vuln.ID,
			Description: vuln.Details,
			References:  dhiReferences(vuln),
			Aliases:     aliases,
			Severities:  severities,
		},
	}}

	for _, handle := range affected {
		in = append(in, handle)
	}
	return transformers.NewEntries(in...), nil
}

func dhiAliases(vuln unmarshal.OSVVulnerability) []string {
	seen := make(map[string]struct{})
	var aliases []string
	for _, alias := range append(append([]string{}, vuln.Aliases...), vuln.Upstream...) {
		if alias == "" || alias == vuln.ID {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	return aliases
}

func dhiReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	refs := make([]db.Reference, 0, len(vuln.References))
	for _, ref := range vuln.References {
		refID := ""
		if ref.Type == osvmodel.ReferenceAdvisory {
			refID = vuln.ID
		}
		refs = append(refs, db.Reference{ID: refID, URL: ref.URL, Tags: []string{string(ref.Type)}})
	}
	return refs
}

func dhiAffectedPackages(vuln unmarshal.OSVVulnerability, aliases []string) ([]db.AffectedPackageHandle, error) {
	var handles []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		if len(affected.Versions) > 0 {
			return nil, fmt.Errorf("invalid DHI affected package in %s: package %s uses explicit versions; DHI OS packages require ECOSYSTEM ranges", vuln.ID, affected.Package.Name)
		}
		identity, err := parseDHIIdentity(affected.Package)
		if err != nil {
			return nil, fmt.Errorf("invalid DHI affected package in %s: %w", vuln.ID, err)
		}

		var ranges []db.Range
		for _, affectedRange := range affected.Ranges {
			if affectedRange.Type != osvmodel.RangeEcosystem {
				return nil, fmt.Errorf("package %s uses unsupported %s range; DHI OS packages require ECOSYSTEM ranges", affected.Package.Name, affectedRange.Type)
			}
			ranges = append(ranges, getGrypeRangesFromRange(affectedRange, identity.packageType.String())...)
		}

		handles = append(handles, db.AffectedPackageHandle{
			OperatingSystem: dhiOperatingSystem(identity.release),
			Package: &db.Package{
				Ecosystem: identity.packageType.String(),
				Name:      name.Normalize(affected.Package.Name, identity.packageType),
			},
			BlobValue: &db.PackageBlob{
				CVEs:       aliases,
				Ranges:     ranges,
				Qualifiers: identity.qualifiers(),
			},
		})
	}
	sort.Sort(internal.ByAffectedPackage(handles))
	return handles, nil
}

type dhiIdentity struct {
	packageType  pkg.Type
	lineage      string
	release      string
	architecture string
}

func (i dhiIdentity) qualifiers() *db.PackageQualifiers {
	if i.architecture == "" {
		return nil
	}
	architecture := i.architecture
	return &db.PackageQualifiers{Architecture: &architecture}
}

func parseDHIIdentity(osvPackage osvmodel.Package) (dhiIdentity, error) {
	parts := strings.Split(osvPackage.Ecosystem, ":")
	if len(parts) != 3 || parts[0] != strings.TrimSuffix(dhiEcosystemPrefix, ":") {
		return dhiIdentity{}, fmt.Errorf("ecosystem %q must be Docker Hardened Images:<Alpine|Debian>:<release>", osvPackage.Ecosystem)
	}
	lineage, release := strings.ToLower(parts[1]), parts[2]
	if !validDHIRelease(release) {
		return dhiIdentity{}, fmt.Errorf("ecosystem %q must use a numeric <major> or <major>.<minor> release", osvPackage.Ecosystem)
	}

	purl, err := packageurl.FromString(osvPackage.Purl)
	if err != nil {
		return dhiIdentity{}, fmt.Errorf("invalid PURL %q: %w", osvPackage.Purl, err)
	}
	if purl.Namespace != "dhi" || purl.Name != osvPackage.Name || purl.Version != "" {
		return dhiIdentity{}, fmt.Errorf("PURL %q must be a versionless DHI PURL for package %q", osvPackage.Purl, osvPackage.Name)
	}

	var packageType pkg.Type
	switch {
	case lineage == "alpine" && purl.Type == packageurl.TypeApk:
		packageType = pkg.ApkPkg
	case lineage == "debian" && purl.Type == packageurl.TypeDebian:
		packageType = pkg.DebPkg
	default:
		return dhiIdentity{}, fmt.Errorf("ecosystem lineage %q does not agree with PURL type %q", lineage, purl.Type)
	}

	qualifiers := make(map[string]string)
	for _, qualifier := range purl.Qualifiers {
		qualifiers[qualifier.Key] = qualifier.Value
	}
	if qualifiers["os_name"] != "dhi" || qualifiers["os_distro"] != lineage || qualifiers["os_version"] != release {
		return dhiIdentity{}, fmt.Errorf("PURL qualifiers must identify dhi/%s/%s", lineage, release)
	}

	return dhiIdentity{packageType: packageType, lineage: lineage, release: release, architecture: qualifiers["arch"]}, nil
}

func validDHIRelease(release string) bool {
	parts := strings.Split(release, ".")
	if len(parts) == 0 || len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func dhiOperatingSystem(release string) *db.OperatingSystem {
	parts := strings.SplitN(release, ".", 2)
	os := &db.OperatingSystem{Name: "dhi", ReleaseID: "dhi", MajorVersion: parts[0]}
	if len(parts) == 2 {
		os.MinorVersion = parts[1]
	}
	return os
}
