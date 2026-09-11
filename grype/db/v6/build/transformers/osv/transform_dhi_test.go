package osv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/syft/syft/pkg"
)

func TestDHIStrategyMatches(t *testing.T) {
	tests := map[string]bool{
		"DHI-CVE-2016-2781-coreutils": true,
		"DHI-mcwm-2wmc-6hv4":          true,
		"CVE-2016-2781":               false,
		"CGA-xcpc-gm23-prj9":          false,
		"":                            false,
	}
	for id, want := range tests {
		t.Run(id, func(t *testing.T) {
			require.Equal(t, want, (dhiStrategy{}).Matches(id))
		})
	}
}

func TestDHITransformAlpineFixture(t *testing.T) {
	vulns := loadFixture(t, "testdata/DHI-CVE-2016-2781-coreutils.json")
	require.Len(t, vulns, 1)

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	related, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	require.Equal(t, "DHI-CVE-2016-2781-coreutils", related.VulnerabilityHandle.Name)
	require.Equal(t, []string{"CVE-2016-2781"}, related.VulnerabilityHandle.BlobValue.Aliases)
	require.Len(t, related.Related, 1)

	handle, ok := related.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok)
	require.Equal(t, &db.OperatingSystem{
		Name:         "dhi",
		ReleaseID:    "dhi",
		MajorVersion: "3",
		MinorVersion: "24",
	}, handle.OperatingSystem)
	require.Equal(t, &db.Package{Ecosystem: "apk", Name: "coreutils"}, handle.Package)
	require.Equal(t, []db.Range{{
		Version: db.Version{Type: "apk", Constraint: "< 9.11-r1"},
		Fix:     &db.Fix{Version: "9.11-r1", State: db.FixedStatus},
	}}, handle.BlobValue.Ranges)
}

func TestDHITransformMetadataAndWithdrawal(t *testing.T) {
	vulns := loadFixture(t, "testdata/DHI-CVE-2016-2781-coreutils.json")
	vuln := vulns[0]
	vuln.Aliases = []string{"CVE-2016-2781", "CVE-2016-2781", vuln.ID}
	vuln.Upstream = []string{"CVE-2016-2781", "GHSA-test-test-test"}
	vuln.References = []osvmodel.Reference{
		{Type: osvmodel.ReferenceAdvisory, URL: "https://example.test/advisory"},
		{Type: osvmodel.ReferenceReport, URL: "https://example.test/report"},
	}
	vuln.Withdrawn = time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)

	entries, err := Transform(vuln, inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	related := entries[0].Data.(transformers.RelatedEntries)
	handle := related.VulnerabilityHandle
	require.Equal(t, db.VulnerabilityRejected, handle.Status)
	require.Equal(t, &vuln.Withdrawn, handle.WithdrawnDate)
	require.Equal(t, []string{"CVE-2016-2781", "GHSA-test-test-test"}, handle.BlobValue.Aliases)
	require.Equal(t, []db.Reference{
		{ID: vuln.ID, URL: "https://example.test/advisory", Tags: []string{"ADVISORY"}},
		{URL: "https://example.test/report", Tags: []string{"REPORT"}},
	}, handle.BlobValue.References)
}

func TestDHITransformSkipsRecordWithoutAffectedPackages(t *testing.T) {
	vulns := loadFixture(t, "testdata/DHI-CVE-2016-2781-coreutils.json")
	vulns[0].Affected = nil
	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestDHITransformRejectsExplicitVersions(t *testing.T) {
	vulns := loadFixture(t, "testdata/DHI-CVE-2016-2781-coreutils.json")
	vulns[0].Affected[0].Versions = []string{"9.11-r0"}
	_, err := Transform(vulns[0], inputProviderState())
	require.ErrorContains(t, err, "uses explicit versions")
}

func TestParseDHIIdentity(t *testing.T) {
	tests := []struct {
		name string
		pkg  osvmodel.Package
		want dhiIdentity
	}{
		{
			name: "Alpine",
			pkg: osvmodel.Package{
				Ecosystem: "Docker Hardened Images:Alpine:3.24",
				Name:      "coreutils",
				Purl:      "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24",
			},
			want: dhiIdentity{packageType: pkg.ApkPkg, lineage: "alpine", release: "3.24"},
		},
		{
			name: "Debian",
			pkg: osvmodel.Package{
				Ecosystem: "Docker Hardened Images:Debian:13",
				Name:      "coreutils",
				Purl:      "pkg:deb/dhi/coreutils?os_distro=debian&os_name=dhi&os_version=13",
			},
			want: dhiIdentity{packageType: pkg.DebPkg, lineage: "debian", release: "13"},
		},
		{
			name: "architecture qualifier",
			pkg: osvmodel.Package{
				Ecosystem: "Docker Hardened Images:Alpine:3.24",
				Name:      "coreutils",
				Purl:      "pkg:apk/dhi/coreutils?arch=aarch64&os_distro=alpine&os_name=dhi&os_version=3.24",
			},
			want: dhiIdentity{packageType: pkg.ApkPkg, lineage: "alpine", release: "3.24", architecture: "aarch64"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDHIIdentity(test.pkg)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestParseDHIIdentityRejectsInvalidPackageIdentity(t *testing.T) {
	tests := []struct {
		name    string
		pkg     osvmodel.Package
		wantErr string
	}{
		{
			name: "SemVer-era ecosystem",
			pkg: osvmodel.Package{
				Ecosystem: "Docker Hardened Images",
				Name:      "coreutils",
				Purl:      "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24",
			},
			wantErr: "must be Docker Hardened Images:<Alpine|Debian>:<release>",
		},
		{
			name: "lineage and type mismatch",
			pkg: osvmodel.Package{
				Ecosystem: "Docker Hardened Images:Debian:13",
				Name:      "coreutils",
				Purl:      "pkg:apk/dhi/coreutils?os_distro=debian&os_name=dhi&os_version=13",
			},
			wantErr: "does not agree with PURL type",
		},
		{
			name: "upstream namespace",
			pkg: osvmodel.Package{
				Ecosystem: "Docker Hardened Images:Alpine:3.24",
				Name:      "coreutils",
				Purl:      "pkg:apk/alpine/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24",
			},
			wantErr: "must be a versionless DHI PURL",
		},
		{
			name: "versioned advisory PURL",
			pkg: osvmodel.Package{
				Ecosystem: "Docker Hardened Images:Alpine:3.24",
				Name:      "coreutils",
				Purl:      "pkg:apk/dhi/coreutils@9.11-r0?os_distro=alpine&os_name=dhi&os_version=3.24",
			},
			wantErr: "must be a versionless DHI PURL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDHIIdentity(test.pkg)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestParseDHIIdentityRejectsInvalidRelease(t *testing.T) {
	tests := []struct {
		name, ecosystem, purl, wantErr string
	}{
		{
			name:      "release mismatch",
			ecosystem: "Docker Hardened Images:Alpine:3.24",
			purl:      "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.25",
			wantErr:   "must identify dhi/alpine/3.24",
		},
		{
			name:      "unrepresentable patch release",
			ecosystem: "Docker Hardened Images:Alpine:3.24.1",
			purl:      "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24.1",
			wantErr:   "must use a numeric <major> or <major>.<minor> release",
		},
		{
			name:      "nonnumeric release",
			ecosystem: "Docker Hardened Images:Alpine:edge",
			purl:      "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=edge",
			wantErr:   "must use a numeric <major> or <major>.<minor> release",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDHIIdentity(osvmodel.Package{Ecosystem: test.ecosystem, Name: "coreutils", Purl: test.purl})
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestDHIArchitectureQualifier(t *testing.T) {
	vulns := loadFixture(t, "testdata/DHI-CVE-2016-2781-coreutils.json")
	vulns[0].Affected[0].Package.Purl = "pkg:apk/dhi/coreutils?arch=aarch64&os_distro=alpine&os_name=dhi&os_version=3.24"

	entries, err := Transform(vulns[0], inputProviderState())
	require.NoError(t, err)
	related := entries[0].Data.(transformers.RelatedEntries)
	handle := related.Related[0].(db.AffectedPackageHandle)
	require.NotNil(t, handle.BlobValue.Qualifiers)
	require.Equal(t, "aarch64", *handle.BlobValue.Qualifiers.Architecture)
}

func TestDHIRangeFormatByLineage(t *testing.T) {
	for _, test := range []struct {
		name       string
		ecosystem  string
		purl       string
		fixed      string
		wantFormat string
	}{
		{
			name:       "APK",
			ecosystem:  "Docker Hardened Images:Alpine:3.24",
			purl:       "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24",
			fixed:      "9.11-r1",
			wantFormat: "apk",
		},
		{
			name:       "dpkg",
			ecosystem:  "Docker Hardened Images:Debian:13",
			purl:       "pkg:deb/dhi/coreutils?os_distro=debian&os_name=dhi&os_version=13",
			fixed:      "9.7-3+dhi4",
			wantFormat: "deb",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, err := parseDHIIdentity(osvmodel.Package{
				Ecosystem: test.ecosystem,
				Name:      "coreutils",
				Purl:      test.purl,
			})
			require.NoError(t, err)
			ranges := eventsToRanges([]osvmodel.Event{{Introduced: "0"}, {Fixed: test.fixed}}, nil, identity.packageType.String())
			require.Len(t, ranges, 1)
			require.Equal(t, test.wantFormat, ranges[0].Version.Type)
		})
	}
}
