package models

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestPackagesAreSorted(t *testing.T) {

	var pkg1 = pkg.Package{
		Name:    "package-1",
		Version: "1.1.1",
		Type:    syftPkg.DebPkg,
	}

	var pkg2 = pkg.Package{
		Name:    "package-2",
		Version: "2.2.2",
		Type:    syftPkg.DebPkg,
	}

	var match1 = match.Match{
		Type: match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-1999-0003",
		},
		Package: pkg1,
	}

	var match2 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-1999-0002",
		},
		Package: pkg1,
	}

	var match3 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-1999-0001",
		},
		Package: pkg1,
	}

	matches := match.NewMatches()
	matches.Add(pkg1, match1, match2, match3)

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
