package internal

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestIsVulnerableTarget(t *testing.T) {
	tests := []struct {
		name            string
		pkg             pkg.Package
		vuln            vulnerability.Vulnerability
		expectedMatches bool
		expectedReason  string
	}{
		{
			name: "OS package should always match",
			pkg: pkg.Package{
				Name:     "openssl",
				Version:  "1.1.1k",
				Type:     syftPkg.RpmPkg,
				Language: syftPkg.UnknownLanguage,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2021-3449",
					Namespace: "nvd:cpe",
				},
				PackageName: "openssl",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", ""),
				},
			},
			expectedMatches: true,
		},
		{
			name: "binary package should always match",
			pkg: pkg.Package{
				Name:     "bash",
				Version:  "5.0.17",
				Type:     syftPkg.BinaryPkg,
				Language: syftPkg.UnknownLanguage,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:gnu:bash:5.0.17:*:*:*:*:*:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2020-12345",
					Namespace: "nvd:cpe",
				},
				PackageName: "bash",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:gnu:bash:5.0.17:*:*:*:*:*:*:*", ""),
				},
			},
			expectedMatches: true,
		},
		{
			name: "unknown package should always match",
			pkg: pkg.Package{
				Name:     "unknown-pkg",
				Version:  "1.0.0",
				Type:     syftPkg.UnknownPkg,
				Language: syftPkg.UnknownLanguage,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:unknown:unknown-pkg:1.0.0:*:*:*:*:*:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2021-98765",
					Namespace: "nvd:cpe",
				},
				PackageName: "unknown-pkg",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:unknown:unknown-pkg:1.0.0:*:*:*:*:*:*:*", ""),
				},
			},
			expectedMatches: true,
		},
		{
			name: "java package should always match",
			pkg: pkg.Package{
				Name:     "log4j-core",
				Version:  "2.14.1",
				Type:     syftPkg.JavaPkg,
				Language: syftPkg.Java,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2021-44228",
					Namespace: "nvd:cpe",
				},
				PackageName: "log4j-core",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", ""),
				},
			},
			expectedMatches: true,
		},
		{
			name: "package with no CPEs should fail",
			pkg: pkg.Package{
				Name:     "example-lib",
				Version:  "1.0.0",
				Type:     syftPkg.NpmPkg,
				Language: syftPkg.JavaScript,
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2021-87654",
					Namespace: "nvd:cpe",
				},
				PackageName: "example-lib",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:example:example-lib:1.0.0:*:*:*:*:*:*:*", ""),
				},
			},
			expectedMatches: false,
			expectedReason:  `vulnerability target software(s) ("") do not align with pkg(example-lib@1.0.0 type="npm" language="javascript" targets="*")`,
		},
		{
			name: "vulnerability with no CPEs should match",
			pkg: pkg.Package{
				Name:     "example-lib",
				Version:  "1.0.0",
				Type:     syftPkg.NpmPkg,
				Language: syftPkg.JavaScript,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:example:example-lib:1.0.0:*:*:*:*:*:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2021-87654",
					Namespace: "nvd:cpe",
				},
				PackageName: "example-lib",
			},
			expectedMatches: true,
		},
		{
			name: "package with wildcard targetSW should match",
			pkg: pkg.Package{
				Name:     "react",
				Version:  "17.0.2",
				Type:     syftPkg.NpmPkg,
				Language: syftPkg.JavaScript,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:facebook:react:17.0.2:*:*:*:*:*:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2021-12345",
					Namespace: "nvd:cpe",
				},
				PackageName: "react",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:facebook:react:17.0.2:*:*:*:*:node.js:*:*", ""),
				},
			},
			expectedMatches: true,
		},
		{
			name: "intersecting target software should match",
			pkg: pkg.Package{
				Name:     "lodash",
				Version:  "4.17.20",
				Type:     syftPkg.NpmPkg,
				Language: syftPkg.JavaScript,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2021-23337",
					Namespace: "nvd:cpe",
				},
				PackageName: "lodash",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*", ""),
				},
			},
			expectedMatches: true,
		},
		{
			name: "non-intersecting target software with matching language should match",
			pkg: pkg.Package{
				Name:     "express",
				Version:  "4.17.1",
				Type:     syftPkg.RpmPkg,     // important!
				Language: syftPkg.JavaScript, // we're using this to match against the vuln TSW
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:expressjs:express:4.17.1:*:*:*:*:react:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2022-24999",
					Namespace: "nvd:cpe",
				},
				PackageName: "express",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:expressjs:express:4.17.1:*:*:*:*:node.js:*:*", ""),
				},
			},
			expectedMatches: true,
		},
		{
			name: "non-intersecting target software with matching package type should fail",
			pkg: pkg.Package{
				Name:     "moment",
				Version:  "2.29.1",
				Type:     syftPkg.NpmPkg, // we're using this to match against the vuln TSW
				Language: syftPkg.CPP,    // important!
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:moment:moment:2.29.1:*:*:*:*:doesntmatter:*:*", ""),
				},
			},
			vuln: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2022-31129",
					Namespace: "nvd:cpe",
				},
				PackageName: "moment",
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:moment:moment:2.29.1:*:*:*:*:node.js:*:*", ""),
				},
			},
			expectedMatches: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, reason := isVulnerableTarget(test.pkg, test.vuln)

			assert.Equal(t, test.expectedMatches, matches, "matches result should be as expected")
			assert.Equal(t, test.expectedReason, reason, "reason should match expected")
		})
	}
}

func Test_isUnknownTarget(t *testing.T) {
	tests := []struct {
		name     string
		targetSW string
		expected bool
	}{
		{name: "supported syft language", targetSW: "python", expected: false},
		{name: "supported non-syft language CPE component", targetSW: "joomla", expected: false},
		{name: "unknown component", targetSW: "abc", expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u := isUnknownTarget(test.targetSW)
			assert.Equal(t, test.expected, u)
		})
	}
}

func TestPkgTypesFromTargetSoftware(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []syftPkg.Type
	}{
		{
			name:     "empty input",
			input:    []string{},
			expected: []syftPkg.Type{},
		},
		{
			name:     "single input with known mapping",
			input:    []string{"node.js"},
			expected: []syftPkg.Type{syftPkg.NpmPkg},
		},
		{
			name:     "multiple inputs with known mappings",
			input:    []string{"python", "ruby", "java"},
			expected: []syftPkg.Type{syftPkg.PythonPkg, syftPkg.GemPkg, syftPkg.JavaPkg},
		},
		{
			name:     "case insensitive input",
			input:    []string{"Python", "RUBY", "Java"},
			expected: []syftPkg.Type{syftPkg.PythonPkg, syftPkg.GemPkg, syftPkg.JavaPkg},
		},
		{
			name:     "mixed known and unknown inputs",
			input:    []string{"python", "unknown", "ruby"},
			expected: []syftPkg.Type{syftPkg.PythonPkg, syftPkg.GemPkg},
		},
		{
			name:     "all unknown inputs",
			input:    []string{"unknown1", "unknown2", "unknown3"},
			expected: []syftPkg.Type{},
		},
		{
			name:     "inputs with spaces and hyphens",
			input:    []string{"redhat-enterprise-linux", "jenkins ci"},
			expected: []syftPkg.Type{syftPkg.RpmPkg, syftPkg.JavaPkg},
		},
		{
			name:     "aliases for the same package type",
			input:    []string{"nodejs", "npm", "javascript"},
			expected: []syftPkg.Type{syftPkg.NpmPkg},
		},
		{
			name:     "wildcards and special characters should be ignored",
			input:    []string{"*", "?", ""},
			expected: []syftPkg.Type{},
		},
		{
			name:     "Linux distributions",
			input:    []string{"alpine", "debian", "redhat", "gentoo"},
			expected: []syftPkg.Type{syftPkg.ApkPkg, syftPkg.DebPkg, syftPkg.RpmPkg, syftPkg.PortagePkg},
		},
		{
			name:     ".NET ecosystem",
			input:    []string{".net", "asp.net", "c#"},
			expected: []syftPkg.Type{syftPkg.DotnetPkg},
		},
		{
			name:     "JavaScript ecosystem",
			input:    []string{"javascript", "node.js", "jquery"},
			expected: []syftPkg.Type{syftPkg.NpmPkg},
		},
		{
			name:     "Java ecosystem",
			input:    []string{"java", "maven", "kafka", "log4j"},
			expected: []syftPkg.Type{syftPkg.JavaPkg},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := pkgTypesFromTargetSoftware(test.input)

			var actualTypes []syftPkg.Type
			for _, typeStr := range actual.List() {
				actualTypes = append(actualTypes, syftPkg.Type(typeStr))
			}

			assert.ElementsMatch(t, test.expected, actualTypes, "package types should match")
		})
	}
}

func TestHasIntersectingTargetSoftware(t *testing.T) {
	tests := []struct {
		name     string
		set1     []string
		set2     []string
		expected bool
	}{
		// basic assertions around sets normalized to package types
		{
			name:     "empty sets",
			set1:     []string{},
			set2:     []string{},
			expected: false,
		},
		{
			name:     "first set empty",
			set1:     []string{},
			set2:     []string{"nodejs", "python"},
			expected: false,
		},
		{
			name:     "second set empty",
			set1:     []string{"java", "ruby"},
			set2:     []string{},
			expected: false,
		},
		{
			name:     "intersecting sets - direct match",
			set1:     []string{"nodejs", "python"},
			set2:     []string{"nodejs", "ruby"},
			expected: true,
		},
		{
			name:     "intersecting sets - aliases",
			set1:     []string{"node.js"},
			set2:     []string{"npm"},
			expected: true,
		},
		{
			name:     "non-intersecting sets",
			set1:     []string{"python", "ruby"},
			set2:     []string{"java", "golang"},
			expected: false,
		},
		{
			name:     "multiple intersections",
			set1:     []string{"python", "ruby", "nodejs"},
			set2:     []string{"javascript", "python", "java"},
			expected: true,
		},
		{
			name:     "case insensitive",
			set1:     []string{"Python", "Ruby"},
			set2:     []string{"python", "java"},
			expected: true,
		},
		{
			name:     "wildcard in first set",
			set1:     []string{"*"},
			set2:     []string{"nodejs", "python"},
			expected: false, // * doesn't map to a package type
		},
		{
			name:     "special linux distro aliases",
			set1:     []string{"rhel", "opensuse"},
			set2:     []string{"redhat"},
			expected: true,
		},
		{
			name:     "different terminology for same ecosystem",
			set1:     []string{"c#"},
			set2:     []string{"dotnet"},
			expected: true,
		},
		{
			name:     "spaces and hyphens handling",
			set1:     []string{"jenkins ci"},
			set2:     []string{"jenkins-ci"},
			expected: true,
		},

		// ecosystem specific cases
		{
			name:     "npm package vs node.js vulnerability",
			set1:     []string{"npm"},
			set2:     []string{"node.js"},
			expected: true,
		},
		{
			name:     "python package vs django vulnerability",
			set1:     []string{"python"},
			set2:     []string{"django"},
			expected: false, // django is not mapped to a package type in the current implementation
		},
		{
			name:     "java package vs multiple java ecosystem vulnerabilities",
			set1:     []string{"java"},
			set2:     []string{"tomcat", "log4j", "maven"},
			expected: true,
		},
		{
			name:     "linux distributions match with different aliases",
			set1:     []string{"redhat"},
			set2:     []string{"centos", "fedora", "rhel"},
			expected: true,
		},
		{
			name:     "no common package types",
			set1:     []string{"python", "ruby"},
			set2:     []string{"nodejs", "php"},
			expected: false,
		},
		{
			name:     "mixed case and formatting",
			set1:     []string{"Node.js", "Ruby-On-Rails"},
			set2:     []string{"javascript", "gem"},
			expected: true,
		},
		{
			name:     ".NET ecosystem different terms",
			set1:     []string{".net-framework"},
			set2:     []string{"c#", "nuget"},
			expected: true,
		},
		{
			name:     "WordPress ecosystem",
			set1:     []string{"wordpress"},
			set2:     []string{"wordpress_plugin"},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set1 := strset.New(test.set1...)
			set2 := strset.New(test.set2...)

			actual := hasIntersectingTargetSoftware(set1, set2)
			assert.Equal(t, test.expected, actual, "integrated target software intersection should match expected")
		})
	}
}
