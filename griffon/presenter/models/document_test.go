package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
	"github.com/nextlinux/griffon/griffon/match"
	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/griffon/vulnerability"
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
			ID: "CVE-1999-0003",
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
			ID: "CVE-1999-0002",
		},
		Package: pkg1,
		Details: match.Details{
			{
				Type: match.ExactIndirectMatch,
			},
		},
	}

	var match3 = match.Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-1999-0001",
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
		Source: &syftSource.Metadata{
			Scheme:        syftSource.DirectoryScheme,
			ImageMetadata: syftSource.ImageMetadata{},
		},
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}
	doc, err := NewDocument(packages, ctx, matches, nil, NewMetadataMock(), nil, nil)
	if err != nil {
		t.Fatalf("unable to get document: %+v", err)
	}

	var actualVulnerabilities []string
	for _, m := range doc.Matches {
		actualVulnerabilities = append(actualVulnerabilities, m.Vulnerability.ID)
	}

	assert.Equal(t, []string{"CVE-1999-0001", "CVE-1999-0002", "CVE-1999-0003"}, actualVulnerabilities)
}

func TestTimestampValidFormat(t *testing.T) {

	matches := match.NewMatches()

	ctx := pkg.Context{
		Source: nil,
		Distro: nil,
	}

	doc, err := NewDocument(nil, ctx, matches, nil, nil, nil, nil)
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
