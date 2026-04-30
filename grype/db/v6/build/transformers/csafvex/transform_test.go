package csafvex

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmarch"
)

var timeVal = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
var listing = provider.File{
	Path:      "some",
	Digest:    "123456",
	Algorithm: "sha256",
}

func inputProviderState() provider.State {
	return provider.State{
		Provider:  "hummingbird",
		Version:   1,
		Processor: "vunnel@1.0.0",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func makeAdvisory(vulns []unmarshal.CSAFVulnerability, tree unmarshal.CSAFProductTree) unmarshal.CSAFVEXAdvisory {
	return unmarshal.CSAFVEXAdvisory{
		Document: unmarshal.CSAFDocument{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Title:       "Test Advisory",
			Publisher: unmarshal.CSAFPublisher{
				Category:  "vendor",
				Name:      "Red Hat Product Security",
				Namespace: "https://www.redhat.com",
			},
			Tracking: unmarshal.CSAFTracking{
				ID:                 "CVE-2026-99999",
				CurrentReleaseDate: "2026-03-20T12:00:00+00:00",
				InitialReleaseDate: "2026-03-01T00:00:00+00:00",
				Status:             "final",
				Version:            "1",
			},
			References: []unmarshal.CSAFReference{
				{Category: "self", Summary: "Advisory", URL: "https://example.com/advisory"},
			},
		},
		ProductTree:     tree,
		Vulnerabilities: vulns,
	}
}

func hummingbirdProductTree() unmarshal.CSAFProductTree {
	return unmarshal.CSAFProductTree{
		Branches: []unmarshal.CSAFBranch{
			{
				Category: "vendor",
				Name:     "Red Hat",
				Branches: []unmarshal.CSAFBranch{
					{
						Category: "product_name",
						Name:     "Red Hat Hardened Images",
						Product: &unmarshal.CSAFProduct{
							Name:      "Red Hat Hardened Images",
							ProductID: "hummingbird-1",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								CPE: "cpe:/a:redhat:hummingbird:1",
							},
						},
					},
					{
						Category: "product_version",
						Name:     "testpkg",
						Product: &unmarshal.CSAFProduct{
							Name:      "testpkg",
							ProductID: "testpkg-0:1.2.3-1.hum1.src",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								PURL: "pkg:rpm/redhat/testpkg@1.2.3-1.hum1?arch=src",
							},
						},
					},
					{
						Category: "product_version",
						Name:     "otherpkg",
						Product: &unmarshal.CSAFProduct{
							Name:      "otherpkg",
							ProductID: "otherpkg",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								PURL: "pkg:rpm/redhat/otherpkg",
							},
						},
					},
				},
			},
		},
		Relationships: []unmarshal.CSAFRelationship{
			{
				Category: "default_component_of",
				FullProductName: unmarshal.CSAFProduct{
					Name:      "testpkg as component of hummingbird",
					ProductID: "hummingbird-1:testpkg-0:1.2.3-1.hum1.src",
				},
				ProductReference:          "testpkg-0:1.2.3-1.hum1.src",
				RelatesToProductReference: "hummingbird-1",
			},
			{
				Category: "default_component_of",
				FullProductName: unmarshal.CSAFProduct{
					Name:      "otherpkg as component of hummingbird",
					ProductID: "hummingbird-1:otherpkg",
				},
				ProductReference:          "otherpkg",
				RelatesToProductReference: "hummingbird-1",
			},
		},
	}
}

func TestTransform_FixedAndNotAffected(t *testing.T) {
	tree := hummingbirdProductTree()
	advisory := makeAdvisory([]unmarshal.CSAFVulnerability{
		{
			CVE:         "CVE-2026-12345",
			Title:       "Test vuln",
			ReleaseDate: "2026-03-01T00:00:00+00:00",
			Notes:       []unmarshal.CSAFNote{{Category: "description", Text: "A test vulnerability.", Title: "Description"}},
			ProductStatus: &unmarshal.CSAFProductStatus{
				Fixed:            []string{"hummingbird-1:testpkg-0:1.2.3-1.hum1.src"},
				KnownNotAffected: []string{"hummingbird-1:otherpkg"},
			},
			Remediations: []unmarshal.CSAFRemediation{
				{
					Category:   "vendor_fix",
					Date:       "2026-03-20T00:00:00+00:00",
					Details:    "Update to latest version",
					ProductIDs: []string{"hummingbird-1:testpkg-0:1.2.3-1.hum1.src"},
					URL:        "https://access.redhat.com/errata/RHSA-2026:1234",
				},
			},
			Scores: []unmarshal.CSAFScore{{
				CVSSV3: &unmarshal.CSAFCVSSV3{
					BaseScore:    5.3,
					BaseSeverity: "MEDIUM",
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
					Version:      "3.1",
				},
				Products: []string{"hummingbird-1:testpkg-0:1.2.3-1.hum1.src", "hummingbird-1:otherpkg"},
			}},
			References: []unmarshal.CSAFReference{{Category: "self", Summary: "CVE page", URL: "https://access.redhat.com/security/cve/CVE-2026-12345"}},
		},
	}, tree)

	got, err := Transform(advisory, inputProviderState())
	require.NoError(t, err)
	require.Len(t, got, 1)

	e, ok := got[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)

	// vulnerability handle
	require.NotNil(t, e.VulnerabilityHandle)
	require.Equal(t, "CVE-2026-12345", e.VulnerabilityHandle.Name)
	require.Equal(t, db.VulnerabilityActive, e.VulnerabilityHandle.Status)
	require.Equal(t, "A test vulnerability.", e.VulnerabilityHandle.BlobValue.Description)
	require.Len(t, e.VulnerabilityHandle.BlobValue.Severities, 1)
	require.Equal(t, db.SeveritySchemeCVSS, e.VulnerabilityHandle.BlobValue.Severities[0].Scheme)

	// should have 2 related entries: 1 affected (fixed) + 1 unaffected
	require.Len(t, e.Related, 2)

	// fixed package → AffectedPackageHandle
	aph, ok := e.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok, "fixed product should be AffectedPackageHandle, got %T", e.Related[0])
	require.Equal(t, "testpkg", aph.Package.Name)
	require.Equal(t, "rpm", aph.Package.Ecosystem)
	require.NotNil(t, aph.OperatingSystem)
	require.Equal(t, "hummingbird", aph.OperatingSystem.Name)
	require.Equal(t, "1", aph.OperatingSystem.MajorVersion)
	require.Len(t, aph.BlobValue.Ranges, 1)
	require.Equal(t, "< 1.2.3-1.hum1", aph.BlobValue.Ranges[0].Version.Constraint)
	require.Equal(t, "rpm", aph.BlobValue.Ranges[0].Version.Type)
	require.NotNil(t, aph.BlobValue.Ranges[0].Fix)
	require.Equal(t, db.FixedStatus, aph.BlobValue.Ranges[0].Fix.State)
	require.Equal(t, "1.2.3-1.hum1", aph.BlobValue.Ranges[0].Fix.Version)
	require.NotNil(t, aph.BlobValue.Ranges[0].Fix.Detail)
	require.NotNil(t, aph.BlobValue.Ranges[0].Fix.Detail.Available)
	require.Equal(t, "advisory", aph.BlobValue.Ranges[0].Fix.Detail.Available.Kind)

	// known_not_affected → UnaffectedPackageHandle
	uph, ok := e.Related[1].(db.UnaffectedPackageHandle)
	require.True(t, ok, "not-affected product should be UnaffectedPackageHandle, got %T", e.Related[1])
	require.Equal(t, "otherpkg", uph.Package.Name)
	require.Equal(t, "rpm", uph.Package.Ecosystem)
	require.NotNil(t, uph.OperatingSystem)
	require.Equal(t, "hummingbird", uph.OperatingSystem.Name)
	require.NotNil(t, uph.BlobValue.Ranges[0].Fix)
	require.Equal(t, db.NotAffectedFixStatus, uph.BlobValue.Ranges[0].Fix.State)
}

func TestTransform_KnownAffected(t *testing.T) {
	tree := hummingbirdProductTree()
	advisory := makeAdvisory([]unmarshal.CSAFVulnerability{
		{
			CVE:   "CVE-2026-99999",
			Title: "Unfixed vuln",
			ProductStatus: &unmarshal.CSAFProductStatus{
				KnownAffected: []string{"hummingbird-1:otherpkg"},
			},
		},
	}, tree)

	got, err := Transform(advisory, inputProviderState())
	require.NoError(t, err)
	require.Len(t, got, 1)

	e, ok := got[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	require.Len(t, e.Related, 1)

	aph, ok := e.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok, "known_affected should be AffectedPackageHandle")
	require.Equal(t, "otherpkg", aph.Package.Name)
	require.Equal(t, "rpm", aph.Package.Ecosystem)
	require.Equal(t, []string{"CVE-2026-99999"}, aph.BlobValue.CVEs)
}

func TestTransform_NoVulnerabilities(t *testing.T) {
	tree := hummingbirdProductTree()
	advisory := makeAdvisory(nil, tree)

	got, err := Transform(advisory, inputProviderState())
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestTransform_UnresolvableProductSkipped(t *testing.T) {
	// product status references a product ID not in the tree
	tree := hummingbirdProductTree()
	advisory := makeAdvisory([]unmarshal.CSAFVulnerability{
		{
			CVE:   "CVE-2026-00001",
			Title: "Ghost product",
			ProductStatus: &unmarshal.CSAFProductStatus{
				KnownAffected: []string{"hummingbird-1:does-not-exist"},
			},
		},
	}, tree)

	got, err := Transform(advisory, inputProviderState())
	require.NoError(t, err)
	require.Len(t, got, 1)

	e, ok := got[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	// the unresolvable product is skipped, so no related entries
	require.Empty(t, e.Related)
}

func TestTransform_OSFromCPE(t *testing.T) {
	tests := []struct {
		name      string
		cpe       string
		wantName  string
		wantMajor string
		wantMinor string
		wantNil   bool
	}{
		{
			name:      "hummingbird URI format",
			cpe:       "cpe:/a:redhat:hummingbird:1",
			wantName:  "hummingbird",
			wantMajor: "1",
		},
		{
			name:      "RHEL URI format",
			cpe:       "cpe:/o:redhat:enterprise_linux:9",
			wantName:  "enterprise_linux",
			wantMajor: "9",
		},
		{
			name:      "CPE 2.3 format with minor version",
			cpe:       "cpe:2.3:o:redhat:enterprise_linux:8.6:*:*:*:*:*:*:*",
			wantName:  "enterprise_linux",
			wantMajor: "8",
			wantMinor: "6",
		},
		{
			name:    "invalid CPE",
			cpe:     "not-a-cpe",
			wantNil: true,
		},
		{
			name:    "too short CPE",
			cpe:     "cpe:/a:vendor",
			wantNil: true,
		},
		{
			name:     "CPE with wildcard version",
			cpe:      "cpe:/a:redhat:hummingbird:*",
			wantName: "hummingbird",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := osFromCPE(tt.cpe)
			if tt.wantNil {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.wantName, got.Name)
			require.Equal(t, tt.wantMajor, got.MajorVersion)
			if tt.wantMinor != "" {
				require.Equal(t, tt.wantMinor, got.MinorVersion)
			}
		})
	}
}

func TestProductIndex(t *testing.T) {
	tree := hummingbirdProductTree()
	idx := newProductIndex(&tree)

	// PURLs should be propagated from branches to relationship composite IDs
	purl, ok := idx.productIDToPURL["hummingbird-1:testpkg-0:1.2.3-1.hum1.src"]
	require.True(t, ok)
	require.Equal(t, "testpkg", purl.Name)
	require.Equal(t, "1.2.3-1.hum1", purl.Version)

	purl, ok = idx.productIDToPURL["hummingbird-1:otherpkg"]
	require.True(t, ok)
	require.Equal(t, "otherpkg", purl.Name)
	require.Equal(t, "", purl.Version)

	// CPE on the platform branch
	cpe, ok := idx.productIDToCPE["hummingbird-1"]
	require.True(t, ok)
	require.Equal(t, "cpe:/a:redhat:hummingbird:1", cpe)

	// relationship platform tracking
	platform, ok := idx.relationshipPlatform["hummingbird-1:testpkg-0:1.2.3-1.hum1.src"]
	require.True(t, ok)
	require.Equal(t, "hummingbird-1", platform)
}

func TestGetSeverities(t *testing.T) {
	vuln := &unmarshal.CSAFVulnerability{
		Scores: []unmarshal.CSAFScore{
			{
				CVSSV3: &unmarshal.CSAFCVSSV3{
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
					Version:      "3.1",
					BaseScore:    5.3,
					BaseSeverity: "MEDIUM",
				},
			},
			{
				CVSSV2: &unmarshal.CSAFCVSSV2{
					VectorString: "AV:N/AC:L/Au:N/C:P/I:N/A:N",
					Version:      "2.0",
					BaseScore:    5.0,
				},
			},
		},
	}

	severities := getSeverities(vuln)
	require.Len(t, severities, 2)
	require.Equal(t, db.SeveritySchemeCVSS, severities[0].Scheme)
	cvss3, ok := severities[0].Value.(db.CVSSSeverity)
	require.True(t, ok)
	require.Equal(t, "3.1", cvss3.Version)

	require.Equal(t, db.SeveritySchemeCVSS, severities[1].Scheme)
	cvss2, ok := severities[1].Value.(db.CVSSSeverity)
	require.True(t, ok)
	require.Equal(t, "2.0", cvss2.Version)
}

// ensure that internal.ParseTime is being used correctly for fix dates
func TestTransform_FixDateParsing(t *testing.T) {
	tree := hummingbirdProductTree()
	advisory := makeAdvisory([]unmarshal.CSAFVulnerability{
		{
			CVE: "CVE-2026-11111",
			ProductStatus: &unmarshal.CSAFProductStatus{
				Fixed: []string{"hummingbird-1:testpkg-0:1.2.3-1.hum1.src"},
			},
			Remediations: []unmarshal.CSAFRemediation{
				{
					Category:   "vendor_fix",
					Date:       "2026-03-20T00:00:00+00:00",
					ProductIDs: []string{"hummingbird-1:testpkg-0:1.2.3-1.hum1.src"},
				},
			},
		},
	}, tree)

	got, err := Transform(advisory, inputProviderState())
	require.NoError(t, err)
	require.Len(t, got, 1)

	e := got[0].Data.(transformers.RelatedEntries)
	aph := e.Related[0].(db.AffectedPackageHandle)

	fix := aph.BlobValue.Ranges[0].Fix
	require.NotNil(t, fix.Detail)
	require.NotNil(t, fix.Detail.Available)
	require.NotNil(t, fix.Detail.Available.Date)

	expected := internal.ParseTime("2026-03-20T00:00:00+00:00")
	if diff := cmp.Diff(expected, fix.Detail.Available.Date); diff != "" {
		t.Errorf("fix date mismatch (-want +got):\n%s", diff)
	}
}

// glibcMixedSrcAndBinaryTree models the shape of the real cve-2026-5928 advisory: hummingbird
// platform contains both `glibc.src` (source RPM) and `glibc` + `glibc-common` (binary RPMs)
// alongside each other. RHEL platforms only carry the source RPM (the typical src-granularity
// disclosure pattern).
func glibcMixedSrcAndBinaryTree() unmarshal.CSAFProductTree {
	return unmarshal.CSAFProductTree{
		Branches: []unmarshal.CSAFBranch{
			{
				Category: "vendor",
				Name:     "Red Hat",
				Branches: []unmarshal.CSAFBranch{
					{
						Category: "product_name",
						Name:     "Red Hat Hardened Images",
						Product: &unmarshal.CSAFProduct{
							Name:      "Red Hat Hardened Images",
							ProductID: "hummingbird-1",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								CPE: "cpe:/a:redhat:hummingbird:1",
							},
						},
					},
					{
						Category: "product_name",
						Name:     "Red Hat Enterprise Linux 9.7.z",
						Product: &unmarshal.CSAFProduct{
							Name:      "Red Hat Enterprise Linux 9.7.z",
							ProductID: "rhel-9.7.z",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								CPE: "cpe:/o:redhat:enterprise_linux:9",
							},
						},
					},
					{
						Category: "product_version",
						Name:     "glibc",
						Product: &unmarshal.CSAFProduct{
							Name:      "glibc",
							ProductID: "glibc",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								PURL: "pkg:rpm/redhat/glibc",
							},
						},
					},
					{
						Category: "product_version",
						Name:     "glibc-common",
						Product: &unmarshal.CSAFProduct{
							Name:      "glibc-common",
							ProductID: "glibc-common",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								PURL: "pkg:rpm/redhat/glibc-common",
							},
						},
					},
					{
						Category: "product_version",
						Name:     "glibc",
						Product: &unmarshal.CSAFProduct{
							Name:      "glibc",
							ProductID: "glibc.src",
							ProductIdentificationHelper: &unmarshal.CSAFProductIdentificationHelper{
								PURL: "pkg:rpm/redhat/glibc?arch=src",
							},
						},
					},
				},
			},
		},
		Relationships: []unmarshal.CSAFRelationship{
			{
				Category:                  "default_component_of",
				FullProductName:           unmarshal.CSAFProduct{Name: "glibc as a component of Red Hat Hardened Images", ProductID: "hummingbird-1:glibc"},
				ProductReference:          "glibc",
				RelatesToProductReference: "hummingbird-1",
			},
			{
				Category:                  "default_component_of",
				FullProductName:           unmarshal.CSAFProduct{Name: "glibc-common as a component of Red Hat Hardened Images", ProductID: "hummingbird-1:glibc-common"},
				ProductReference:          "glibc-common",
				RelatesToProductReference: "hummingbird-1",
			},
			{
				Category:                  "default_component_of",
				FullProductName:           unmarshal.CSAFProduct{Name: "glibc.src as a component of Red Hat Hardened Images", ProductID: "hummingbird-1:glibc.src"},
				ProductReference:          "glibc.src",
				RelatesToProductReference: "hummingbird-1",
			},
			{
				Category:                  "default_component_of",
				FullProductName:           unmarshal.CSAFProduct{Name: "glibc.src as a component of Red Hat Enterprise Linux 9.7.z", ProductID: "rhel-9.7.z:glibc.src"},
				ProductReference:          "glibc.src",
				RelatesToProductReference: "rhel-9.7.z",
			},
		},
	}
}

func TestTransform_DropsSrcWhenSameNameBinaryPresent(t *testing.T) {
	// hummingbird-1 platform has both glibc (binary) and glibc.src (source); the redundant
	// src must be dropped so upstream-search filtering doesn't FP-match siblings like
	// glibc-minimal-langpack via upstream=glibc. The RHEL platform's glibc.src has no sibling
	// binary in this advisory and must be retained — that's the standard src-granularity
	// disclosure pattern that grype's RPM matcher relies on for indirect upstream matches.
	tree := glibcMixedSrcAndBinaryTree()
	advisory := makeAdvisory([]unmarshal.CSAFVulnerability{
		{
			CVE: "CVE-2026-5928",
			ProductStatus: &unmarshal.CSAFProductStatus{
				KnownAffected: []string{
					"hummingbird-1:glibc",
					"hummingbird-1:glibc-common",
					"hummingbird-1:glibc.src",
					"rhel-9.7.z:glibc.src",
				},
			},
		},
	}, tree)

	got, err := Transform(advisory, inputProviderState())
	require.NoError(t, err)
	require.Len(t, got, 1)

	e := got[0].Data.(transformers.RelatedEntries)

	type emitted struct {
		name string
		os   string
		arch string
	}
	var seen []emitted
	for _, r := range e.Related {
		aph, ok := r.(db.AffectedPackageHandle)
		if !ok {
			continue
		}
		osName := ""
		if aph.OperatingSystem != nil {
			osName = aph.OperatingSystem.Name
		}
		var arch string
		if aph.BlobValue != nil && aph.BlobValue.Qualifiers != nil && aph.BlobValue.Qualifiers.RpmArch != nil {
			arch = *aph.BlobValue.Qualifiers.RpmArch
		}
		seen = append(seen, emitted{name: aph.Package.Name, os: osName, arch: arch})
	}

	want := []emitted{
		{name: "glibc", os: "hummingbird", arch: rpmarch.ArchBinaryNoArchSpecified},
		{name: "glibc-common", os: "hummingbird", arch: rpmarch.ArchBinaryNoArchSpecified},
		{name: "glibc", os: "enterprise_linux", arch: rpmarch.ArchSource},
	}

	require.ElementsMatch(t, want, seen, "hummingbird:glibc.src should be dropped (sibling binary present); rhel-9.7.z:glibc.src should survive")
}

func TestTransform_RpmArchTaggingForFixedAndUnaffected(t *testing.T) {
	// Verify the rpmarch tag is set for the fixed and known_not_affected paths too — not
	// just known_affected — and that the value follows the same arch-from-PURL rule.
	tree := hummingbirdProductTree()
	advisory := makeAdvisory([]unmarshal.CSAFVulnerability{
		{
			CVE:         "CVE-2026-77777",
			ReleaseDate: "2026-03-01T00:00:00+00:00",
			ProductStatus: &unmarshal.CSAFProductStatus{
				Fixed:            []string{"hummingbird-1:testpkg-0:1.2.3-1.hum1.src"},
				KnownNotAffected: []string{"hummingbird-1:otherpkg"},
			},
		},
	}, tree)

	got, err := Transform(advisory, inputProviderState())
	require.NoError(t, err)
	require.Len(t, got, 1)

	e := got[0].Data.(transformers.RelatedEntries)
	require.Len(t, e.Related, 2)

	aph, ok := e.Related[0].(db.AffectedPackageHandle)
	require.True(t, ok)
	require.NotNil(t, aph.BlobValue.Qualifiers)
	require.NotNil(t, aph.BlobValue.Qualifiers.RpmArch)
	require.Equal(t, rpmarch.ArchSource, *aph.BlobValue.Qualifiers.RpmArch, "fixed src rpm should carry rpmarch=src")

	uph, ok := e.Related[1].(db.UnaffectedPackageHandle)
	require.True(t, ok)
	require.NotNil(t, uph.BlobValue.Qualifiers)
	require.NotNil(t, uph.BlobValue.Qualifiers.RpmArch)
	require.Equal(t, rpmarch.ArchBinaryNoArchSpecified, *uph.BlobValue.Qualifiers.RpmArch, "binary rpm without an arch qualifier should carry the synthesized sentinel")
}
