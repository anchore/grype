package match

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

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
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-d",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		// shuffle vulnerability id, package name, package version, and package type
		fifth, third, first, second, fourth,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second, third, fourth, fifth}, matches.Sorted())

}

func TestMatchesSortByVulnerability(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackage(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-c",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackageVersion(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func TestMatchesSortByPackageType(t *testing.T) {
	first := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0010",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
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
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())

}

func assertMatchOrder(t *testing.T, expected, actual []Match) {

	var expectedStr []string
	for _, e := range expected {
		expectedStr = append(expectedStr, e.Package.Name)
	}

	var actualStr []string
	for _, a := range actual {
		actualStr = append(actualStr, a.Package.Name)
	}

	// makes this easier on the eyes to sanity check...
	require.Equal(t, expectedStr, actualStr)

	// make certain the fields are what you'd expect
	assert.Equal(t, expected, actual)
}

func assertIgnoredMatchOrder(t *testing.T, expected, actual []IgnoredMatch) {

	var expectedStr []string
	for _, e := range expected {
		expectedStr = append(expectedStr, e.Package.Name)
	}

	var actualStr []string
	for _, a := range actual {
		actualStr = append(actualStr, a.Package.Name)
	}

	// makes this easier on the eyes to sanity check...
	require.Equal(t, expectedStr, actualStr)

	// make certain the fields are what you'd expect
	assert.Equal(t, expected, actual)
}
