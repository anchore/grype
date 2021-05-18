package match

import (
	"testing"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func TestMatchesSortMixedDimensions(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
		},
		Package: pkg.Package{
			Name:    "package-a",
			Version: "1.0.0",
			Type:    syftPkg.NpmPkg,
		},
	}
	third := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
		},
		Package: pkg.Package{
			Name:    "package-a",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	fourth := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
		},
		Package: pkg.Package{
			Name:    "package-c",
			Version: "3.0.0",
			Type:    syftPkg.ApkPkg,
		},
	}
	fifth := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
		},
		Package: pkg.Package{
			Name:    "package-d",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	matches := NewMatches()
	input := []Match{
		// shuffle vulnerability id, package name, package version, and package type
		fifth, third, first, second, fourth,
	}
	for _, i := range input {
		matches.Add(i.Package, i)
	}

	expected := []Match{
		first, second, third, fourth, fifth,
	}

	assert.Equal(t, expected, matches.Sorted())

}

func TestMatchesSortByVulnerability(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{second, first}

	matches := NewMatches()
	for _, i := range input {
		matches.Add(i.Package, i)
	}

	assert.Equal(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackage(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-c",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{second, first}

	matches := NewMatches()
	for _, i := range input {
		matches.Add(i.Package, i)
	}

	assert.Equal(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackageVersion(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{second, first}

	matches := NewMatches()
	for _, i := range input {
		matches.Add(i.Package, i)
	}

	assert.Equal(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackageType(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.ApkPkg,
		},
	}
	second := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{second, first}

	matches := NewMatches()
	for _, i := range input {
		matches.Add(i.Package, i)
	}

	assert.Equal(t, []Match{first, second}, matches.Sorted())

}
