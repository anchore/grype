package osv

import (
	"reflect"
	"testing"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// TestRootioTransform exercises the rootio strategy end-to-end against the
// five canonical Root IO fixture shapes:
//
//   - ROOT-OS-ALPINE-318: apk package with Alpine OS metadata
//   - ROOT-OS-DEBIAN-bookworm: deb package with Debian OS metadata (numeric ver)
//   - ROOT-OS-UBUNTU-2004: deb package with Ubuntu OS metadata
//   - ROOT-APP-NPM: npm language package (no OS metadata, name with @scope)
//   - ROOT-APP-PYPI: python language package (PEP 503 name normalization)
//
// Assertions are loose (presence + key field equality) rather than full
// struct-equality because the rootio strategy's outputs span several distinct
// ecosystems with different version-format and OS-resolution choices that
// would be tedious to spell out in cmp.Diff form for every case. Each test
// confirms: vulnerability emitted with the right CVE in aliases, exactly one
// UnaffectedPackageHandle produced (NAK semantics), the package name
// normalized as expected, the RootIO qualifier set, and the unaffected
// constraint uses ">=" with the rootio backport version.
func TestRootioTransform(t *testing.T) {
	tests := []struct {
		name               string
		fixturePath        string
		expectedPkgName    string
		expectedCVE        string
		expectedFixVersion string
	}{
		// Expected names are the rootio-prefixed names verbatim from the OSV
		// records — preserving the contributor's intent for this merge commit.
		// A maintainer-authored follow-up commit may switch the storage shape
		// (e.g. to AffectedPackageHandle with the same prefixed names) once
		// the design is settled.
		{
			name:               "Root IO Alpine OS package",
			fixturePath:        "testdata/ROOT-OS-ALPINE-318-CVE-2000-0548.json",
			expectedPkgName:    "rootio-util-linux",
			expectedCVE:        "CVE-2000-0548",
			expectedFixVersion: "2.38.1-r10071",
		},
		{
			name:               "Root IO NPM package",
			fixturePath:        "testdata/ROOT-APP-NPM-CVE-2022-25883.json",
			expectedPkgName:    "@rootio/semver",
			expectedCVE:        "CVE-2022-25883",
			expectedFixVersion: "7.5.2-root.io.1",
		},
		{
			name: "Root IO PyPI package",
			// PEP 503 normalization converts rootio_requests → rootio-requests.
			fixturePath:        "testdata/ROOT-APP-PYPI-CVE-2025-30473.json",
			expectedPkgName:    "rootio-requests",
			expectedCVE:        "CVE-2025-30473",
			expectedFixVersion: "2.31.0+root.io.1",
		},
		{
			name:               "Root IO Debian package",
			fixturePath:        "testdata/ROOT-OS-DEBIAN-bookworm-CVE-2025-53014.json",
			expectedPkgName:    "rootio-imagemagick",
			expectedCVE:        "CVE-2025-53014",
			expectedFixVersion: "8:7.1.1.43+dfsg1-1+deb13u1.root.io.1",
		},
		{
			name:               "Root IO Ubuntu package",
			fixturePath:        "testdata/ROOT-OS-UBUNTU-2004-CVE-2024-12345.json",
			expectedPkgName:    "rootio-openssl",
			expectedCVE:        "CVE-2024-12345",
			expectedFixVersion: "1.1.1f-1ubuntu2.root.io.1",
		},
	}

	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			vulns := loadFixture(tt, test.fixturePath)
			require.Len(tt, vulns, 1, "fixture should contain exactly one vulnerability")

			vuln := vulns[0]
			require.True(tt, rootioStrategy{}.Matches(vuln.ID), "ID prefix should match the rootio strategy")

			entries, err := Transform(vuln, inputProviderState())
			require.NoError(tt, err)
			require.Len(tt, entries, 1, "one RelatedEntries wrapping the vuln + unaffected handle(s)")

			rel, ok := entries[0].Data.(transformers.RelatedEntries)
			require.True(tt, ok, "entry data should be RelatedEntries")

			require.NotNil(tt, rel.VulnerabilityHandle)
			require.Equal(tt, "osv", rel.VulnerabilityHandle.ProviderID)
			require.NotNil(tt, rel.VulnerabilityHandle.BlobValue)
			require.Contains(tt, rel.VulnerabilityHandle.BlobValue.Aliases, test.expectedCVE)

			require.Len(tt, rel.Related, 1, "rootio NAK emits exactly one unaffected package handle per fixture")
			uph, ok := rel.Related[0].(db.UnaffectedPackageHandle)
			require.True(tt, ok, "related entry must be UnaffectedPackageHandle (NAK), not AffectedPackageHandle")

			require.NotNil(tt, uph.Package)
			require.Equal(tt, test.expectedPkgName, uph.Package.Name)

			require.NotNil(tt, uph.BlobValue)
			require.Contains(tt, uph.BlobValue.CVEs, test.expectedCVE,
				"rootio NAK CVEs must include the upstream CVE so the distro matcher's identity-match across name boundaries works")

			require.NotNil(tt, uph.BlobValue.Qualifiers, "rootio unaffected record must carry qualifiers")
			require.NotNil(tt, uph.BlobValue.Qualifiers.RootIO, "RootIO qualifier must be set")
			require.True(tt, *uph.BlobValue.Qualifiers.RootIO)

			require.Len(tt, uph.BlobValue.Ranges, 1)
			constraint := uph.BlobValue.Ranges[0].Version.Constraint
			require.Contains(tt, constraint, ">=", "unaffected range constraint must use >= (versions at/above the rootio fix are safe)")
			require.Contains(tt, constraint, test.expectedFixVersion)
		})
	}
}

// TestRootioTransform_RelatedToAliases verifies the alias-augmentation path
// for the real-world rootio shape where the upstream CVE lives in `related`
// (not `aliases`). The augmented set must land on both the vulnerability
// blob's Aliases and each UnaffectedPackageHandle's PackageBlob.CVEs so the
// distro matcher's cross-name identity match works.
func TestRootioTransform_RelatedToAliases(t *testing.T) {
	vuln := unmarshal.OSVVulnerability{}
	vuln.ID = "ROOT-OS-UBUNTU-2204-CVE-2024-2236"
	vuln.Related = []string{"CVE-2024-2236"}
	vuln.Affected = []models.Affected{
		{
			Package: models.Package{
				Ecosystem: "Ubuntu:22.04",
				Name:      "rootio-libgcrypt20",
			},
			Ranges: []models.Range{
				{
					Type: models.RangeEcosystem,
					Events: []models.Event{
						{Introduced: "0"},
						{Fixed: "1.9.4-3ubuntu3.root.io.2"},
					},
				},
			},
		},
	}

	require.True(t, rootioStrategy{}.Matches(vuln.ID))

	entries, err := Transform(vuln, inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)

	rel, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	require.Contains(t, rel.VulnerabilityHandle.BlobValue.Aliases, "CVE-2024-2236",
		"related CVE must augment the vulnerability blob's aliases")

	require.Len(t, rel.Related, 1)
	uph, ok := rel.Related[0].(db.UnaffectedPackageHandle)
	require.True(t, ok)
	require.Contains(t, uph.BlobValue.CVEs, "CVE-2024-2236",
		"related CVE must also be in PackageBlob.CVEs so disclosures.Remove(naks) identity-matches across name boundaries")
}

// TestRootioStrategy_Matches covers the ID-prefix dispatch for the rootio
// strategy. Negative cases ensure non-rootio IDs don't accidentally route
// here.
func TestRootioStrategy_Matches(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"ROOT-OS-UBUNTU-2004-CVE-2024-12345", true},
		{"ROOT-OS-DEBIAN-bookworm-CVE-2025-53014", true},
		{"ROOT-OS-ALPINE-318-CVE-2000-0548", true},
		{"ROOT-APP-NPM-CVE-2022-25883", true},
		{"ROOT-APP-PYPI-CVE-2025-30473", true},
		{"ALSA-2025:7467", false},
		{"BIT-apache-2020-11984", false},
		{"CVE-2024-12345", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := (rootioStrategy{}).Matches(tt.id); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

// TestRootioPackageType covers the ecosystem-to-package-type mapping for the
// language ecosystems (npm, PyPI, Maven) and the OS ecosystems (Alpine,
// Debian, Ubuntu) that rootio emits. PURL-driven detection is exercised via
// the fixture-driven TestRootioTransform.
func TestRootioPackageType(t *testing.T) {
	tests := []struct {
		ecosystem string
		want      string // pkg.Type.String() form for readability
	}{
		{"npm", "npm"},
		{"PyPI", "python"},
		{"pypi", "python"},
		{"pip", "python"},
		{"python", "python"},
		{"Maven", "java-archive"},
		{"java", "java-archive"},
		{"Alpine:3.18", "apk"},
		{"Debian:13", "deb"},
		{"Ubuntu:20.04", "deb"},
		{"Bitnami", ""},      // not a rootio ecosystem; strategy returns empty
		{"AlmaLinux:8", ""},  // alma is the alma strategy's domain
		{"", ""},
		{"NoColon", ""},
	}
	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			got := rootioEcosystemPackageType(tt.ecosystem)
			if string(got) != tt.want {
				t.Errorf("rootioEcosystemPackageType(%q) = %q, want %q", tt.ecosystem, got, tt.want)
			}
		})
	}
}

// TestRootioOSFromEcosystem exercises OS metadata extraction for ROOT-OS-*
// ecosystem strings, including the non-numeric "bookworm"/"jammy" label
// version path.
func TestRootioOSFromEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      *db.OperatingSystem
	}{
		{
			name:      "Ubuntu numeric version",
			ecosystem: "Ubuntu:20.04",
			want: &db.OperatingSystem{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
		},
		{
			name:      "Alpine major.minor",
			ecosystem: "Alpine:3.18",
			want: &db.OperatingSystem{
				Name:         "alpine",
				MajorVersion: "3",
				MinorVersion: "18",
			},
		},
		{
			name:      "Debian numeric version",
			ecosystem: "Debian:13",
			want: &db.OperatingSystem{
				Name:         "debian",
				MajorVersion: "13",
			},
		},
		{
			name:      "Debian codename takes label-version path",
			ecosystem: "Debian:bookworm",
			want: &db.OperatingSystem{
				Name:         "debian",
				LabelVersion: "bookworm",
			},
		},
		{
			name:      "non-OS ecosystem (npm) returns nil",
			ecosystem: "npm",
			want:      nil,
		},
		{
			name:      "unsupported OS returns nil",
			ecosystem: "Fedora:38",
			want:      nil,
		},
		{
			name:      "empty string returns nil",
			ecosystem: "",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rootioOSFromEcosystem(tt.ecosystem)
			if got == nil && tt.want == nil {
				return
			}
			if got == nil || tt.want == nil {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			// codename lookup may populate Codename; assert on the explicit fields
			// the test cares about rather than full struct equality.
			if got.Name != tt.want.Name ||
				got.MajorVersion != tt.want.MajorVersion ||
				got.MinorVersion != tt.want.MinorVersion ||
				got.LabelVersion != tt.want.LabelVersion {
				t.Errorf("got %+v, want %+v (ignoring Codename)", got, tt.want)
			}
		})
	}
}

// compile-time guard: keep reflect import in use even if assertions evolve
// (some prior test variants used reflect.DeepEqual; leaving it imported keeps
// future helper additions friction-free).
var _ = reflect.DeepEqual
