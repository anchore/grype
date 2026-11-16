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
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

const (
	dhiEcosystemName = "Docker Hardened Images"
	dhiLineageAlpine = "alpine"
	dhiLineageDebian = "debian"
	dhiNamespace     = "dhi"
)

type dhiStrategy struct{}

// Matches reports whether an OSV record uses the DHI advisory ID prefix.
func (dhiStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "DHI-")
}

// Transform converts a DHI OSV record into vulnerability and affected-package entries. A record
// with no affected packages, the shape of a withdrawn DHI advisory, yields the vulnerability alone.
// An affected package that cannot be read as a DHI package is logged and left out, so one
// unexpected entry does not fail the database build.
func (dhiStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	aliases := dhiAliases(vuln)
	affected := dhiAffectedPackages(vuln, aliases)
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

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
			References:  cgReferences(vuln),
			Aliases:     aliases,
			Severities:  severities,
		},
	}}

	for _, handle := range affected {
		in = append(in, handle)
	}
	return transformers.NewEntries(in...), nil
}

// dhiAliases combines and deduplicates the aliases and upstream IDs of a DHI advisory.
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

// dhiAffectedPackages converts each affected DHI package into a database handle. An entry with no
// DHI package identity is skipped, because a handle with no operating system would match the
// package on every distribution. An entry that states neither versions nor ranges is skipped,
// because a handle with no ranges matches every version and the record states none. An active
// record that lists affected packages and keeps none is logged once more, since it is written
// with the same shape as a withdrawn advisory.
func dhiAffectedPackages(vuln unmarshal.OSVVulnerability, aliases []string) []db.AffectedPackageHandle {
	var handles []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		identity, err := parseDHIIdentity(affected.Package)
		if err != nil {
			log.WithFields("id", vuln.ID, "package", affected.Package.Name, "error", err).Warn("skipping DHI affected package")
			continue
		}

		ranges, allVersions := dhiRanges(affected, identity.packageType.String())
		if len(ranges) == 0 && !allVersions {
			log.WithFields("id", vuln.ID, "package", affected.Package.Name).Warn("skipping DHI affected package with neither affected versions nor ranges")
			continue
		}

		handles = append(handles, db.AffectedPackageHandle{
			OperatingSystem: dhiOperatingSystem(identity.release),
			Package: &db.Package{
				Ecosystem: identity.packageType.String(),
				Name:      name.Normalize(affected.Package.Name, identity.packageType),
			},
			// PackageBlob.CVEs carries the augmented alias list (aliases plus upstream) rather than the
			// bare vuln.Aliases that alma preserves: DHI records name their CVE only in `upstream`, and
			// the distro-fixed ignore reasons must surface that CVE alongside the DHI advisory ID.
			BlobValue: &db.PackageBlob{
				CVEs:       aliases,
				Ranges:     ranges,
				Qualifiers: identity.qualifiers(),
			},
		})
	}
	if len(vuln.Affected) > 0 && len(handles) == 0 && vuln.Withdrawn.IsZero() {
		log.WithFields("id", vuln.ID, "affected", len(vuln.Affected)).Warn("DHI advisory lists affected packages and none could be read; it is written with no affected packages")
	}
	sort.Sort(internal.ByAffectedPackage(handles))
	return handles
}

// dhiRanges converts the affected ranges and the enumerated affected versions of a DHI package
// into database ranges. An ECOSYSTEM range carries versions in the package format (apk or deb);
// any other range type uses the default mapping, as the Chainguard strategy does.
//
// OSV gives affected[].versions and affected[].ranges union semantics: a version is affected if
// it is listed or falls within a range. Generated DHI records carry both for assessed intervals
// and only versions for under_investigation assessments, so exact versions become "= <version>"
// ranges alongside the interval ranges. A version under investigation is therefore reported as
// affected until the feed drops it: the record carries no field that tells the two apart.
//
// allVersions is true when a range is introduced at "0" and never closed, which states that
// every version is affected. That is stored as no ranges at all, so the listed versions add
// nothing and are left out.
func dhiRanges(affected osvmodel.Affected, packageFormat string) (ranges []db.Range, allVersions bool) {
	for _, affectedRange := range affected.Ranges {
		rangeType := packageFormat
		if affectedRange.Type != osvmodel.RangeEcosystem {
			rangeType = defaultRangeType(affectedRange.Type)
		}
		converted := getGrypeRangesFromRange(affectedRange, rangeType)
		if len(converted) == 0 && introducesAllVersions(affectedRange) {
			return nil, true
		}
		ranges = append(ranges, converted...)
	}

	seen := make(map[string]struct{})
	for _, v := range affected.Versions {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		ranges = append(ranges, db.Range{
			Version: db.Version{Type: packageFormat, Constraint: fmt.Sprintf("= %s", v)},
		})
	}

	return ranges, false
}

// introducesAllVersions reports whether a range has an introduced event, which with no database
// range produced from it means the range opens at "0" and has no fixed or last_affected event.
func introducesAllVersions(r osvmodel.Range) bool {
	for _, e := range r.Events {
		if e.Introduced != "" {
			return true
		}
	}
	return false
}

type dhiIdentity struct {
	packageType  pkg.Type
	release      string
	architecture string
}

// qualifiers returns the package qualifiers used to constrain matching for this identity.
func (i dhiIdentity) qualifiers() *db.PackageQualifiers {
	if i.architecture == "" {
		return nil
	}
	architecture := i.architecture
	return &db.PackageQualifiers{Architecture: &architecture}
}

// parseDHIIdentity validates and extracts the package lineage, release, type, and architecture.
func parseDHIIdentity(osvPackage osvmodel.Package) (dhiIdentity, error) {
	parts := strings.Split(osvPackage.Ecosystem, ":")
	if len(parts) != 3 || parts[0] != dhiEcosystemName {
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
	if purl.Namespace != dhiNamespace || purl.Name != osvPackage.Name || purl.Version != "" {
		return dhiIdentity{}, fmt.Errorf("PURL %q must be a versionless DHI PURL for package %q", osvPackage.Purl, osvPackage.Name)
	}

	var packageType pkg.Type
	switch {
	case lineage == dhiLineageAlpine && purl.Type == packageurl.TypeApk:
		packageType = pkg.ApkPkg
	case lineage == dhiLineageDebian && purl.Type == packageurl.TypeDebian:
		packageType = pkg.DebPkg
	default:
		return dhiIdentity{}, fmt.Errorf("ecosystem lineage %q does not agree with PURL type %q", lineage, purl.Type)
	}

	qualifiers := make(map[string]string)
	for _, qualifier := range purl.Qualifiers {
		qualifiers[qualifier.Key] = qualifier.Value
	}
	// The ecosystem is the source of truth for the lineage and release. The os_* qualifiers are optional,
	// but when present they must agree with it.
	for key, want := range map[string]string{"os_name": dhiNamespace, "os_distro": lineage, "os_version": release} {
		if got, ok := qualifiers[key]; ok && got != want {
			return dhiIdentity{}, fmt.Errorf("PURL qualifiers must identify dhi/%s/%s", lineage, release)
		}
	}

	return dhiIdentity{packageType: packageType, release: release, architecture: qualifiers["arch"]}, nil
}

// validDHIRelease reports whether a release is a numeric major or major-minor version.
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

// dhiOperatingSystem maps a DHI release into Grype's operating-system representation.
func dhiOperatingSystem(release string) *db.OperatingSystem {
	parts := strings.SplitN(release, ".", 2)
	os := &db.OperatingSystem{Name: dhiNamespace, ReleaseID: dhiNamespace, MajorVersion: parts[0]}
	if len(parts) == 2 {
		os.MinorVersion = parts[1]
	}
	return os
}
