package osv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// cleanstartRollingOS is the OS row every version-less CleanStart record should
// produce. CleanStart is a rolling apk distro, so it carries the same
// Name/ReleaseID/LabelVersion shape as chainguard and wolfi — that trio is what
// operating_system_specifier_overrides matches on.
func cleanstartRollingOS() *db.OperatingSystem {
	return &db.OperatingSystem{
		Name:         "cleanstart",
		ReleaseID:    "cleanstart",
		LabelVersion: "rolling",
	}
}

func TestCleanstartStrategy_Matches(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"CLEANSTART-2026-AA09584", true},
		{"CLEANSTART-2025-CN65903", true},
		{"CGA-xcpc-gm23-prj9", false},
		{"ALSA-2023:1234", false},
		{"CVE-2026-1111", false},
		{"GHSA-hr2v-4r36-88hr", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			assert.Equal(t, tt.want, cleanstartStrategy{}.Matches(tt.id))
		})
	}
}

// TestCleanstartOSFromEcosystem pins the ecosystem spellings the advisory feed
// actually emits. Both "CleanStart" and "clnstrt" are in use and must resolve
// to the same distro; anything else must return nil so the record is not
// silently attributed to CleanStart.
func TestCleanstartOSFromEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      *db.OperatingSystem
	}{
		{
			name:      "canonical spelling, no version",
			ecosystem: "CleanStart",
			want:      cleanstartRollingOS(),
		},
		{
			name:      "short spelling, no version",
			ecosystem: "clnstrt",
			want:      cleanstartRollingOS(),
		},
		{
			name:      "spelling is case insensitive",
			ecosystem: "CLEANSTART",
			want:      cleanstartRollingOS(),
		},
		{
			name:      "trailing colon with no version is still rolling",
			ecosystem: "CleanStart:",
			want:      cleanstartRollingOS(),
		},
		{
			name:      "versioned ecosystem",
			ecosystem: "CleanStart:3.20",
			want: &db.OperatingSystem{
				Name:         "cleanstart",
				ReleaseID:    "cleanstart",
				MajorVersion: "3",
				MinorVersion: "20",
			},
		},
		{
			name:      "short spelling, versioned",
			ecosystem: "clnstrt:3",
			want: &db.OperatingSystem{
				Name:         "cleanstart",
				ReleaseID:    "cleanstart",
				MajorVersion: "3",
			},
		},
		{
			name:      "empty ecosystem",
			ecosystem: "",
			want:      nil,
		},
		{
			name:      "a different distro is not claimed",
			ecosystem: "Alpine:3.20",
			want:      nil,
		},
		{
			name:      "a prefix match is not enough",
			ecosystem: "cleanstartish",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cleanstartOSFromEcosystem(tt.ecosystem))
		})
	}
}

// TestCleanstartAliases covers the field the CleanStart feed actually uses.
// Every record in the feed carries its CVE/GHSA ids in `upstream` and leaves
// `aliases`/`related` empty, so reading only `aliases` would store every
// advisory with no CVE linkage at all.
func TestCleanstartAliases(t *testing.T) {
	tests := []struct {
		name string
		vuln unmarshal.OSVVulnerability
		want []string
	}{
		{
			name: "upstream is the dominant shape",
			vuln: osvVuln(func(v *osvmodel.Vulnerability) {
				v.Upstream = []string{"CVE-2026-1111", "ghsa-hr2v-4r36-88hr"}
			}),
			want: []string{"CVE-2026-1111", "ghsa-hr2v-4r36-88hr"},
		},
		{
			name: "aliases and related are still honored",
			vuln: osvVuln(func(v *osvmodel.Vulnerability) {
				v.Aliases = []string{"CVE-2026-2222"}
				v.Related = []string{"CVE-2026-3333"}
				v.Upstream = []string{"CVE-2026-1111"}
			}),
			want: []string{"CVE-2026-2222", "CVE-2026-1111", "CVE-2026-3333"},
		},
		{
			name: "duplicates across fields collapse",
			vuln: osvVuln(func(v *osvmodel.Vulnerability) {
				v.Aliases = []string{"CVE-2026-1111"}
				v.Upstream = []string{"CVE-2026-1111", "CVE-2026-1111"}
			}),
			want: []string{"CVE-2026-1111"},
		},
		{
			name: "blank entries are dropped",
			vuln: osvVuln(func(v *osvmodel.Vulnerability) {
				v.Upstream = []string{"", "  ", "CVE-2026-1111"}
			}),
			want: []string{"CVE-2026-1111"},
		},
		{
			// A blanket ToUpper would turn this into "GHSA-HR2V-4R36-88HR",
			// which is not a well-formed GHSA id — the suffix is lower-case by
			// construction. Normalizing the feed's mixed casing is the
			// producer's job, not the transformer's.
			name: "identifier casing is preserved verbatim",
			vuln: osvVuln(func(v *osvmodel.Vulnerability) {
				v.Upstream = []string{"ghsa-hr2v-4r36-88hr", "GHSA-hr2v-4r36-88hz"}
			}),
			want: []string{"ghsa-hr2v-4r36-88hr", "GHSA-hr2v-4r36-88hz"},
		},
		{
			name: "no identifiers at all",
			vuln: osvVuln(func(v *osvmodel.Vulnerability) {}),
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cleanstartAliases(tt.vuln))
		})
	}
}

// TestCleanstartAliases_NoSharedBacking guards the reason cleanstartAliases
// allocates fresh each call: the slice is handed to both the vulnerability blob
// and every package blob, and a shared backing array would let one append
// overwrite another's contents.
func TestCleanstartAliases_NoSharedBacking(t *testing.T) {
	vuln := osvVuln(func(v *osvmodel.Vulnerability) {
		v.Upstream = []string{"CVE-2026-1111"}
	})

	first := cleanstartAliases(vuln)
	second := cleanstartAliases(vuln)
	require.Equal(t, first, second)

	second = append(second, "CVE-2026-9999")
	assert.Equal(t, []string{"CVE-2026-1111"}, first, "appending to one result must not disturb another")
}

// TestCleanstartTransform exercises the real advisory shape end to end: an
// ECOSYSTEM range of introduced=0 / fixed=X becomes an *affected* "< X"
// constraint (not a NAK/unaffected row), the upstream ids reach both blobs, and
// the OS row is the rolling one.
func TestCleanstartTransform(t *testing.T) {
	vuln := osvVuln(func(v *osvmodel.Vulnerability) {
		v.ID = "CLEANSTART-2026-AA09584"
		v.Details = "ghsa-hr2v-4r36-88hr affects multiple packages."
		v.Upstream = []string{"ghsa-hr2v-4r36-88hr"}
		v.Published = time.Date(2026, time.September, 18, 10, 18, 47, 0, time.UTC)
		v.Modified = time.Date(2026, time.May, 1, 9, 5, 7, 0, time.UTC)
		v.References = []osvmodel.Reference{
			{Type: osvmodel.ReferenceAdvisory, URL: "https://example.com/CLEANSTART-2026-AA09584.json"},
			{Type: osvmodel.ReferenceWeb, URL: "https://osv.dev/vulnerability/ghsa-hr2v-4r36-88hr"},
		}
		v.Affected = []osvmodel.Affected{
			cleanstartAffected("CleanStart", "linkerd2", "26.1.4-r0"),
			// The same package can appear twice with different fix versions;
			// each affected entry stays its own row.
			cleanstartAffected("clnstrt", "linkerd2", "26.4.2"),
		}
	})

	entries, err := cleanstartStrategy{}.Transform(vuln, provider.State{Provider: "osv"})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	related, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)

	require.NotNil(t, related.VulnerabilityHandle)
	assert.Equal(t, "CLEANSTART-2026-AA09584", related.VulnerabilityHandle.Name)
	assert.Equal(t, []string{"ghsa-hr2v-4r36-88hr"}, related.VulnerabilityHandle.BlobValue.Aliases)
	assert.Equal(t, []db.Reference{
		{ID: "CLEANSTART-2026-AA09584", URL: "https://example.com/CLEANSTART-2026-AA09584.json", Tags: []string{"ADVISORY"}},
		{URL: "https://osv.dev/vulnerability/ghsa-hr2v-4r36-88hr", Tags: []string{"WEB"}},
	}, related.VulnerabilityHandle.BlobValue.References)

	require.Len(t, related.Related, 2)
	var constraints []string
	for _, r := range related.Related {
		aph, ok := r.(db.AffectedPackageHandle)
		require.True(t, ok, "CleanStart records describe affected ranges, not unaffected ones")
		assert.Equal(t, cleanstartRollingOS(), aph.OperatingSystem)
		assert.Equal(t, "apk", aph.Package.Ecosystem)
		assert.Equal(t, "linkerd2", aph.Package.Name)
		assert.Equal(t, []string{"ghsa-hr2v-4r36-88hr"}, aph.BlobValue.CVEs)
		require.Len(t, aph.BlobValue.Ranges, 1)
		rng := aph.BlobValue.Ranges[0]
		assert.Equal(t, "apk", rng.Version.Type)
		constraints = append(constraints, rng.Version.Constraint)
	}
	assert.ElementsMatch(t, []string{"< 26.1.4-r0", "< 26.4.2"}, constraints)
}

// TestCleanstartTransform_UnknownEcosystem covers a record whose ecosystem is
// not CleanStart at all: the package row is still emitted, but with no OS
// attached, so it can never be matched against a CleanStart image.
func TestCleanstartTransform_UnknownEcosystem(t *testing.T) {
	vuln := osvVuln(func(v *osvmodel.Vulnerability) {
		v.ID = "CLEANSTART-2026-AA09584"
		v.Affected = []osvmodel.Affected{cleanstartAffected("Alpine:3.20", "linkerd2", "26.1.4-r0")}
	})

	entries, err := cleanstartStrategy{}.Transform(vuln, provider.State{Provider: "osv"})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	related := entries[0].Data.(transformers.RelatedEntries)
	require.Len(t, related.Related, 1)
	assert.Nil(t, related.Related[0].(db.AffectedPackageHandle).OperatingSystem)
}

// TestCleanstartTransform_Withdrawn pins the behaviour that keeps withdrawn
// advisories from becoming false positives. A majority of the CleanStart feed
// is withdrawn, and the OnlyNonWithdrawnVulnerabilities filter that govulndb
// and github rely on is never applied on the distro matcher path that
// CleanStart rows travel (FindResultsByDistro searches ByPackageName +
// ByDistro + OnlyQualifiedPackages only). So the affected-package rows have to
// be withheld here; a Rejected status alone would still match.
func TestCleanstartTransform_Withdrawn(t *testing.T) {
	withdrawnAt := time.Date(2026, time.September, 18, 11, 59, 1, 0, time.UTC)

	vuln := osvVuln(func(v *osvmodel.Vulnerability) {
		v.ID = "CLEANSTART-2026-AG84392"
		v.Upstream = []string{"CVE-2022-48174"}
		v.Withdrawn = withdrawnAt
		v.Affected = []osvmodel.Affected{cleanstartAffected("CleanStart", "busybox", "1.36.1-r2")}
	})

	entries, err := cleanstartStrategy{}.Transform(vuln, provider.State{Provider: "osv"})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	related := entries[0].Data.(transformers.RelatedEntries)

	require.NotNil(t, related.VulnerabilityHandle)
	assert.Equal(t, db.VulnerabilityRejected, related.VulnerabilityHandle.Status)
	require.NotNil(t, related.VulnerabilityHandle.WithdrawnDate)
	assert.Equal(t, withdrawnAt, *related.VulnerabilityHandle.WithdrawnDate)

	// the handle is still emitted (so the advisory stays visible), but nothing
	// the distro matcher can find is
	assert.Empty(t, related.Related, "withdrawn advisories must emit no affected-package rows")

	// the record itself is unchanged otherwise
	assert.Equal(t, []string{"CVE-2022-48174"}, related.VulnerabilityHandle.BlobValue.Aliases)
}

// TestCleanstartTransform_NotWithdrawn is the control for the case above.
func TestCleanstartTransform_NotWithdrawn(t *testing.T) {
	vuln := osvVuln(func(v *osvmodel.Vulnerability) {
		v.ID = "CLEANSTART-2026-EH13874"
		v.Upstream = []string{"CVE-2022-48174"}
		v.Affected = []osvmodel.Affected{cleanstartAffected("CleanStart", "busybox", "1.35.0-r17")}
	})

	entries, err := cleanstartStrategy{}.Transform(vuln, provider.State{Provider: "osv"})
	require.NoError(t, err)
	related := entries[0].Data.(transformers.RelatedEntries)

	assert.Equal(t, db.VulnerabilityActive, related.VulnerabilityHandle.Status)
	assert.Nil(t, related.VulnerabilityHandle.WithdrawnDate)
	require.Len(t, related.Related, 1)
	assert.Equal(t,
		"< 1.35.0-r17",
		related.Related[0].(db.AffectedPackageHandle).BlobValue.Ranges[0].Version.Constraint,
	)
}

// osvVuln builds an OSVVulnerability with the given mutations applied.
func osvVuln(mutate func(*osvmodel.Vulnerability)) unmarshal.OSVVulnerability {
	var v unmarshal.OSVVulnerability
	v.SchemaVersion = "1.7.3"
	mutate((*osvmodel.Vulnerability)(&v))
	return v
}

// cleanstartAffected builds the affected shape the feed emits: a single
// ECOSYSTEM range running from introduced=0 up to the fix.
func cleanstartAffected(ecosystem, pkgName, fixedVersion string) osvmodel.Affected {
	return osvmodel.Affected{
		Package: osvmodel.Package{Ecosystem: ecosystem, Name: pkgName},
		Ranges: []osvmodel.Range{
			{
				Type: osvmodel.RangeEcosystem,
				Events: []osvmodel.Event{
					{Introduced: "0"},
					{Fixed: fixedVersion},
				},
			},
		},
	}
}
