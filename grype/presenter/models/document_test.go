package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
)

func TestPackagesAreSorted(t *testing.T) {
	var pkg1 = pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.1.1",
		Type:    syftPkg.DebPkg,
	}

	var pkg2 = pkg.Package{
		ID:      "package-2-id",
		Name:    "package-2",
		Version: "2.2.2",
		Type:    syftPkg.DebPkg,
	}

	var match1 = match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-1999-0003"},
		},
		Package: pkg1,
		Details: match.Details{
			{
				Type: match.ExactDirectMatch,
			},
		},
	}

	var match2 = match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-1999-0002"},
		},
		Package: pkg2,
		Details: match.Details{
			{
				Type: match.ExactIndirectMatch,
			},
		},
	}

	var match3 = match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-1999-0001"},
		},
		Package: pkg1,
		Details: match.Details{
			{
				Type: match.ExactIndirectMatch,
			},
		},
	}

	matches := match.NewMatches()
	matches.Add(match1, match2, match3)

	packages := []pkg.Package{pkg1, pkg2}

	ctx := pkg.Context{
		Source: &syftSource.Description{
			Metadata: syftSource.DirectoryMetadata{},
		},
	}
	doc, err := NewDocument(clio.Identification{}, packages, ctx, matches, nil, NewMetadataMock(), nil, nil, SortByPackage, true, nil)
	if err != nil {
		t.Fatalf("unable to get document: %+v", err)
	}

	var actualPackages []string
	for _, m := range doc.Matches {
		actualPackages = append(actualPackages, m.Artifact.Name)
	}

	// sort packages first
	assert.Equal(t, []string{"package-1", "package-1", "package-2"}, actualPackages)

	var actualVulnerabilities []string
	for _, m := range doc.Matches {
		actualVulnerabilities = append(actualVulnerabilities, m.Vulnerability.ID)
	}

	// sort vulnerabilities second
	assert.Equal(t, []string{"CVE-1999-0001", "CVE-1999-0003", "CVE-1999-0002"}, actualVulnerabilities)
}

func TestFixSuggestedVersion(t *testing.T) {

	var pkg1 = pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.1.1",
		Type:    syftPkg.PythonPkg,
	}

	var match1 = match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Fix: vulnerability.Fix{
				Versions: []string{"1.0.0", "1.2.0", "1.1.2"},
			},
			Reference: vulnerability.Reference{ID: "CVE-1999-0003"},
		},
		Package: pkg1,
		Details: match.Details{
			{
				Type: match.ExactDirectMatch,
			},
		},
	}

	matches := match.NewMatches()
	matches.Add(match1)

	packages := []pkg.Package{pkg1}

	ctx := pkg.Context{
		Source: &syftSource.Description{
			Metadata: syftSource.DirectoryMetadata{},
		},
	}
	doc, err := NewDocument(clio.Identification{}, packages, ctx, matches, nil, NewMetadataMock(), nil, nil, SortByPackage, true, nil)
	if err != nil {
		t.Fatalf("unable to get document: %+v", err)
	}

	actualSuggestedFixedVersion := doc.Matches[0].MatchDetails[0].Fix.SuggestedVersion

	assert.Equal(t, "1.1.2", actualSuggestedFixedVersion)
}

func TestTimestampValidFormat(t *testing.T) {

	matches := match.NewMatches()

	ctx := pkg.Context{
		Source: nil,
	}

	doc, err := NewDocument(clio.Identification{}, nil, ctx, matches, nil, nil, nil, nil, SortByPackage, true, nil)
	if err != nil {
		t.Fatalf("unable to get document: %+v", err)
	}

	assert.NotEmpty(t, doc.Descriptor.Timestamp)
	// Check format is RFC3339 compatible e.g. 2023-04-21T00:22:06.491137+01:00
	_, timeErr := time.Parse(time.RFC3339, doc.Descriptor.Timestamp)
	if timeErr != nil {
		t.Fatalf("unable to parse time: %+v", timeErr)
	}

}

func TestConfigurableTimestamp(t *testing.T) {

	matches := match.NewMatches()
	ctx := pkg.Context{
		Source: nil,
		Distro: nil,
	}

	doc, err := NewDocument(clio.Identification{}, nil, ctx, matches, nil, nil, nil, nil, SortByPackage, false, nil)
	if err != nil {
		t.Fatalf("unable to get document: %+v", err)
	}

	assert.Empty(t, doc.Descriptor.Timestamp)

}

func TestBuildPackageAlerts(t *testing.T) {
	ubuntu := &distro.Distro{Type: distro.Ubuntu, Version: "18.04"}

	pkg1 := pkg.Package{
		ID:      "pkg-1-id",
		Name:    "openssl",
		Version: "1.1.1",
		Type:    syftPkg.DebPkg,
		Distro:  ubuntu,
	}

	pkg2 := pkg.Package{
		ID:      "pkg-2-id",
		Name:    "curl",
		Version: "7.60.0",
		Type:    syftPkg.DebPkg,
		Distro:  ubuntu,
	}

	tests := []struct {
		name       string
		data       *DistroAlertData
		wantLen    int
		wantAlerts map[string][]AlertType // package ID -> expected alert types
	}{
		{
			name:       "no distro alert data",
			data:       nil,
			wantLen:    0,
			wantAlerts: map[string][]AlertType{},
		},
		{
			name: "EOL distro packages",
			data: &DistroAlertData{
				EOLDistroPackages: []pkg.Package{pkg1, pkg2},
			},
			wantLen: 2,
			wantAlerts: map[string][]AlertType{
				"pkg-1-id": {AlertTypeDistroEOL},
				"pkg-2-id": {AlertTypeDistroEOL},
			},
		},
		{
			name: "disabled distro packages",
			data: &DistroAlertData{
				DisabledDistroPackages: []pkg.Package{pkg1},
			},
			wantLen: 1,
			wantAlerts: map[string][]AlertType{
				"pkg-1-id": {AlertTypeDistroDisabled},
			},
		},
		{
			name: "mixed distro packages",
			data: &DistroAlertData{
				EOLDistroPackages:      []pkg.Package{pkg1},
				DisabledDistroPackages: []pkg.Package{pkg2},
			},
			wantLen: 2,
			wantAlerts: map[string][]AlertType{
				"pkg-1-id": {AlertTypeDistroEOL},
				"pkg-2-id": {AlertTypeDistroDisabled},
			},
		},
		{
			name: "duplicate packages with multiple alert types",
			data: &DistroAlertData{
				DisabledDistroPackages: []pkg.Package{pkg1},
				EOLDistroPackages:      []pkg.Package{pkg1}, // Same package in both
			},
			wantLen: 1,
			wantAlerts: map[string][]AlertType{
				"pkg-1-id": {AlertTypeDistroDisabled, AlertTypeDistroEOL}, // Both alerts
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := buildPackageAlerts(tc.data)
			assert.Len(t, result, tc.wantLen)

			for _, pa := range result {
				expectedAlerts, ok := tc.wantAlerts[pa.Package.ID]
				assert.True(t, ok, "unexpected package in result: %s", pa.Package.ID)

				if tc.wantLen > 0 {
					assert.Len(t, pa.Alerts, len(expectedAlerts), "package should have expected number of alerts")
					// Check alert types match
					for i, expectedType := range expectedAlerts {
						assert.Equal(t, expectedType, pa.Alerts[i].Type)
						// Check message contains distro name
						assert.Contains(t, pa.Alerts[i].Message, "ubuntu")
					}
				}
			}
		})
	}
}
