package match

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
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
	sixth := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
			Fix: vulnerability.Fix{
				Versions: []string{"2.0.0", "1.0.0"},
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-d",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	seventh := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
			Fix: vulnerability.Fix{
				Versions: []string{"2.0.1"},
			},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-d",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	eighth := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2020-0020",
			Fix: vulnerability.Fix{
				Versions: []string{"3.0.0"},
			},
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
		fifth, eighth, third, seventh, first, sixth, second, fourth,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second, third, fourth, fifth, sixth, seventh, eighth}, matches.Sorted())

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

func TestMatches_AllByPkgID(t *testing.T) {
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

	expected := map[pkg.ID][]Match{
		first.Package.ID: {
			first,
		},
		second.Package.ID: {
			second,
		},
	}

	assert.Equal(t, expected, matches.AllByPkgID())

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

func TestMatches_Diff(t *testing.T) {
	a := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID:        "vuln-a",
			Namespace: "name-a",
		},
		Package: pkg.Package{
			ID: "package-a",
		},
	}

	b := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID:        "vuln-b",
			Namespace: "name-b",
		},
		Package: pkg.Package{
			ID: "package-b",
		},
	}

	c := Match{
		Vulnerability: vulnerability.Vulnerability{
			ID:        "vuln-c",
			Namespace: "name-c",
		},
		Package: pkg.Package{
			ID: "package-c",
		},
	}

	tests := []struct {
		name    string
		subject Matches
		other   Matches
		want    Matches
	}{
		{
			name:    "no diff",
			subject: NewMatches(a, b, c),
			other:   NewMatches(a, b, c),
			want:    newMatches(),
		},
		{
			name:    "extra items in subject",
			subject: NewMatches(a, b, c),
			other:   NewMatches(a, b),
			want:    NewMatches(c),
		},
		{
			// this demonstrates that this is not meant to implement a symmetric diff
			name:    "extra items in other (results in no diff)",
			subject: NewMatches(a, b),
			other:   NewMatches(a, b, c),
			want:    NewMatches(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, &tt.want, tt.subject.Diff(tt.other), "Diff(%v)", tt.other)
		})
	}
}
