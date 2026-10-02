package name

import (
	"testing"

	"github.com/stretchr/testify/assert"

	grypePkg "github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSwiftResolver_Normalize(t *testing.T) {
	resolver := SwiftResolver{}

	// the DB is case-insensitive for name columns, and Swift repository paths
	// are commonly mixed-case, so the name is passed through untouched
	assert.Equal(t, "github.com/Alamofire/Alamofire", resolver.Normalize("github.com/Alamofire/Alamofire"))
	assert.Equal(t, "", resolver.Normalize(""))
}

func TestSwiftResolver_Names(t *testing.T) {
	tests := []struct {
		name     string
		pkg      grypePkg.Package
		expected []string
	}{
		{
			name: "purl namespace yields the repository path advisories are keyed on",
			pkg: grypePkg.Package{
				Name: "vapor",
				PURL: "pkg:swift/github.com/vapor/vapor@4.0.0",
			},
			expected: []string{"vapor", "github.com/vapor/vapor"},
		},
		{
			name: "mixed-case repository path is preserved",
			pkg: grypePkg.Package{
				Name: "swift-nio",
				PURL: "pkg:swift/github.com/apple/Swift-NIO@2.29.0",
			},
			expected: []string{"swift-nio", "github.com/apple/Swift-NIO"},
		},
		{
			name: "no namespace leaves only the catalogued name",
			pkg: grypePkg.Package{
				Name: "local-package",
				PURL: "pkg:swift/local-package@1.0.0",
			},
			expected: []string{"local-package"},
		},
		{
			name: "no purl leaves only the catalogued name",
			pkg: grypePkg.Package{
				Name: "vapor",
			},
			expected: []string{"vapor"},
		},
		{
			name: "malformed purl does not lose the catalogued name",
			pkg: grypePkg.Package{
				Name: "vapor",
				PURL: "not-a-purl",
			},
			expected: []string{"vapor"},
		},
	}

	resolver := SwiftResolver{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, resolver.Names(test.pkg))
		})
	}
}

func TestPackageNames_Swift(t *testing.T) {
	// the resolver must be reachable through the registry, not just directly
	names := PackageNames(grypePkg.Package{
		Name: "vapor",
		Type: syftPkg.SwiftPkg,
		PURL: "pkg:swift/github.com/vapor/vapor@4.0.0",
	})

	assert.ElementsMatch(t, []string{"vapor", "github.com/vapor/vapor"}, names)
}

func TestPackageNames_CocoapodsUnaffected(t *testing.T) {
	// CocoaPods purls carry no namespace; the package must be untouched
	names := PackageNames(grypePkg.Package{
		Name: "Alamofire",
		Type: syftPkg.CocoapodsPkg,
		PURL: "pkg:cocoapods/Alamofire@5.9.0",
	})

	assert.Equal(t, []string{"Alamofire"}, names)
}
