package apk

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSecDBOnlyMatch(t *testing.T) {
	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			// ID doesn't match - this is the key for comparison in the matcher
			ID:        "CVE-2020-2",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(secDbVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{

			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": secDbVuln.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-2",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestBothSecdbAndNvdMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			// ID *does* match - this is the key for comparison in the matcher
			ID:        "CVE-2020-1",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(nvdVuln, secDbVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{
			// ensure the SECDB record is preferred over the NVD record
			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": secDbVuln.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestBothSecdbAndNvdMatches_DifferentFixInfo(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 1.0.0", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
		Fix: vulnerability.Fix{
			Versions: []string{"1.0.0"},
			State:    vulnerability.FixStateFixed,
		},
	}

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			// ID *does* match - this is the key for comparison in the matcher
			ID:        "CVE-2020-1",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.12", version.ApkFormat),
		// SecDB indicates Alpine have backported a fix to v0.9...
		Fix: vulnerability.Fix{
			Versions: []string{"0.9.12"},
			State:    vulnerability.FixStateFixed,
		},
	}
	vp := mock.VulnerabilityProvider(nvdVuln, secDbVuln)
	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{
			// ensure the SECDB record is preferred over the NVD record
			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": secDbVuln.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestBothSecdbAndNvdMatches_DifferentPackageName(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.UnknownFormat),
		// Note: the product name is NOT the same as the target package name
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:lib_vnc_project-(server):libvncumbrellaproject:*:*:*:*:*:*:*:*", ""),
		},
	}

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			// ID *does* match - this is the key for comparison in the matcher
			ID:        "CVE-2020-1",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(nvdVuln, secDbVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			// Note: the product name is NOT the same as the package name
			cpe.Must("cpe:2.3:a:*:libvncumbrellaproject:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{
			// ensure the SECDB record is preferred over the NVD record
			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": secDbVuln.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdOnlyMatches(t *testing.T) {
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}
	vp := mock.VulnerabilityProvider(nvdVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{

			Vulnerability: nvdVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
					},
					Found: match.CPEResult{
						CPEs:              []string{nvdVuln.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: nvdVuln.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdOnlyMatches_FixInNvd(t *testing.T) {
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
		Fix: vulnerability.Fix{
			Versions: []string{"0.9.12"},
			State:    vulnerability.FixStateFixed,
		},
	}
	vp := mock.VulnerabilityProvider(nvdVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	vulnFound := nvdVuln
	// Important: for alpine matcher, fix version can come from secDB but _not_ from
	// NVD data.
	vulnFound.Fix = vulnerability.Fix{State: vulnerability.FixStateUnknown}

	expected := []match.Match{
		{
			Vulnerability: vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
					},
					Found: match.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesProperVersionFiltering(t *testing.T) {
	nvdVulnMatch := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}
	nvdVulnNoMatch := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-2",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}
	vp := mock.VulnerabilityProvider(nvdVulnMatch, nvdVulnNoMatch)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11-r10",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{
			Vulnerability: nvdVulnMatch,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.11-r10",
						},
					},
					Found: match.CPEResult{
						CPEs:              []string{nvdVulnMatch.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: nvdVulnMatch.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesWithSecDBFix(t *testing.T) {
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("> 0.9.0, < 0.10.0", version.UnknownFormat), // note: this is not normal NVD configuration, but has the desired effect of a "wide net" for vulnerable indication
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.11", version.ApkFormat), // note: this does NOT include 0.9.11, so NVD and SecDB mismatch here... secDB should trump in this case
	}

	vp := mock.VulnerabilityProvider(nvdVuln, secDbVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	var expected []match.Match

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesNoConstraintWithSecDBFix(t *testing.T) {
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("", version.UnknownFormat), // note: empty value indicates that all versions are vulnerable
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.11", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(nvdVuln, secDbVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	var expected []match.Match

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNVDMatchCanceledByOriginPackageInSecDB(t *testing.T) {
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2015-3211",
			Namespace: "nvd:cpe",
		},
		PackageName: "php-fpm",
		Constraint:  version.MustGetConstraint("", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:php-fpm:php-fpm:-:*:*:*:*:*:*:*", ""),
		},
	}
	secDBVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2015-3211",
			Namespace: "wolfi:distro:wolfi:rolling",
		},
		PackageName: "php-8.3",
		Constraint:  version.MustGetConstraint("< 0", version.ApkFormat),
	}
	vp := mock.VulnerabilityProvider(nvdVuln, secDBVuln)

	m := Matcher{}
	d, err := distro.New(distro.Wolfi, "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "php-8.3-fpm", // the package will not match anything
		Version: "8.3.11-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:php-fpm:php-fpm:8.3.11-r0:*:*:*:*:*:*:*", ""),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name:    "php-8.3", // this upstream should match
				Version: "8.3.11-r0",
			},
		},
	}

	var expected []match.Match

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestDistroMatchBySourceIndirection(t *testing.T) {

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			// ID doesn't match - this is the key for comparison in the matcher
			ID:        "CVE-2020-2",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "musl",
		Constraint:  version.MustGetConstraint("<= 1.3.3-r0", version.ApkFormat),
	}
	vp := mock.VulnerabilityProvider(secDbVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
		},
	}

	expected := []match.Match{
		{

			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactIndirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "musl",
							"version": p.Version,
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": secDbVuln.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-2",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestSecDBMatchesStillCountedWithCpeErrors(t *testing.T) {
	// this should match the test package
	// the test package will have no CPE causing an error,
	// but the error should not cause the secDB matches to fail
	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-2",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "musl",
		Constraint:  version.MustGetConstraint("<= 1.3.3-r0", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(secDbVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
		CPEs: []cpe.CPE{},
	}

	expected := []match.Match{
		{

			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactIndirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "musl",
							"version": p.Version,
						},
						"namespace": "secdb:distro:alpine:3.12",
					},
					Found: map[string]interface{}{
						"versionConstraint": secDbVuln.Constraint.String(),
						"vulnerabilityID":   "CVE-2020-2",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNVDMatchBySourceIndirection(t *testing.T) {
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "musl",
		Constraint:  version.MustGetConstraint("<= 1.3.3-r0", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl:musl:*:*:*:*:*:*:*:*", ""),
		},
	}
	vp := mock.VulnerabilityProvider(nvdVuln)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", ""),
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", ""),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
	}

	expected := []match.Match{
		{
			Vulnerability: nvdVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:musl:musl:1.3.2-r0:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.CPEPackageParameter{
							Name:    "musl",
							Version: "1.3.2-r0",
						},
					},
					Found: match.CPEResult{
						CPEs:              []string{nvdVuln.CPEs[0].Attributes.BindToFmtString()},
						VersionConstraint: nvdVuln.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	var opts = []cmp.Option{
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func Test_nakConstraint(t *testing.T) {
	tests := []struct {
		name    string
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
	}{
		{
			name: "matches apk",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 0", version.ApkFormat),
			},
			matches: true,
		},
		{
			name: "not match due to type",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 0", version.SemanticFormat),
			},
			matches: false,
		},
		{
			name: "not match",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 2.0", version.SemanticFormat),
			},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := nakConstraint.MatchesVulnerability(tt.input)
			wantErr := require.NoError
			if tt.wantErr != nil {
				wantErr = tt.wantErr
			}
			wantErr(t, err)
			require.Equal(t, tt.matches, matches)
		})
	}
}
