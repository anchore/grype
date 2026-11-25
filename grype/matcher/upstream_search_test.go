package matcher

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/internal/architecture"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/apk"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// searchRecorder records every search a matcher makes, as search rules see it, and finds vuln for
// each, so every stage of a matcher's search runs (e.g. an EUS resolution search follows only a
// disclosure).
type searchRecorder struct {
	vulnerability.Provider
	vuln     vulnerability.Vulnerability
	searches [][]vulnerability.Criteria
}

var _ v6.SearchRuleProvider = (*searchRecorder)(nil)

func (r *searchRecorder) SearchRewrites(_ pkg.Package, cs []vulnerability.Criteria) ([][]vulnerability.Criteria, bool) {
	r.searches = append(r.searches, cs)
	return nil, false
}

func (r *searchRecorder) FindVulnerabilities(...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{r.vuln}, nil
}

// searchedName is the package name a search is for: its name criteria, else its CPE's product.
func searchedName(cs []vulnerability.Criteria) string {
	for _, c := range cs {
		switch c := c.(type) {
		case *search.PackageNameCriteria:
			return c.PackageName
		case *search.CPECriteria:
			return c.CPE.Attributes.Product
		}
	}
	return ""
}

// Search rules tell an upstream search from a direct one by its architecture, so every search a matcher
// makes for one of the package's upstreams must be by the source architecture, and every search for the
// package itself by the package's own.
func TestMatchers_MarkEveryUpstreamSearch(t *testing.T) {
	const arch = "x86_64"
	const binary, upstream = "bin", "src"

	tests := []struct {
		name    string
		matcher match.Matcher
		pkgType syftPkg.Type
		distro  *distro.Distro
		version string
		format  version.Format
	}{
		{name: "apk", matcher: &apk.Matcher{}, pkgType: syftPkg.ApkPkg, distro: distro.New(distro.Alpine, "3.18", ""), version: "1.0-r0", format: version.ApkFormat},
		{name: "dpkg", matcher: dpkg.NewDpkgMatcher(dpkg.MatcherConfig{UseCPEs: true}), pkgType: syftPkg.DebPkg, distro: distro.New(distro.Debian, "12", ""), version: "1.0-1", format: version.DebFormat},
		{name: "dpkg ubuntu esm", matcher: dpkg.NewDpkgMatcher(dpkg.MatcherConfig{}), pkgType: syftPkg.DebPkg, distro: distro.New(distro.Ubuntu, "16.04+esm", ""), version: "1.0-1", format: version.DebFormat},
		{name: "rpm", matcher: rpm.NewRpmMatcher(rpm.MatcherConfig{UseCPEs: true}), pkgType: syftPkg.RpmPkg, distro: distro.New(distro.RedHat, "9", ""), version: "1.0-1.el9", format: version.RpmFormat},
		{name: "rpm redhat eus", matcher: rpm.NewRpmMatcher(rpm.MatcherConfig{}), pkgType: syftPkg.RpmPkg, distro: distro.New(distro.RedHat, "9.4+eus", ""), version: "1.0-1.el9", format: version.RpmFormat},
		{name: "rpm almalinux", matcher: rpm.NewRpmMatcher(rpm.MatcherConfig{}), pkgType: syftPkg.RpmPkg, distro: distro.New(distro.AlmaLinux, "8", ""), version: "1.0-1.el8", format: version.RpmFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{
				ID:        pkg.ID(binary),
				Name:      binary,
				Version:   tt.version,
				Arch:      arch,
				Type:      tt.pkgType,
				Distro:    tt.distro,
				Upstreams: []pkg.UpstreamPackage{{Name: upstream}},
				CPEs:      []cpe.CPE{cpe.Must("cpe:2.3:a:"+binary+":"+binary+":1.0:*:*:*:*:*:*:*", "")},
			}
			vp := &searchRecorder{
				Provider: mock.VulnerabilityProvider(),
				vuln: vulnerability.Vulnerability{
					Reference:   vulnerability.Reference{ID: "CVE-2024-0001", Namespace: "test"},
					PackageName: binary,
					Constraint:  version.MustGetConstraint("< 99", tt.format),
				},
			}

			_, _, err := tt.matcher.Match(vp, p)
			require.NoError(t, err)

			var upstreamSearches int
			for _, cs := range vp.searches {
				switch searchedName(cs) {
				case binary:
					assert.Equal(t, []string{arch}, searchedArchs(cs), "a search for the package itself is by its architecture: %s", summarize(cs))
				case upstream:
					assert.Equal(t, []string{architecture.ArchSource}, searchedArchs(cs), "a search for an upstream is by the source architecture: %s", summarize(cs))
					upstreamSearches++
				default:
					t.Errorf("unexpected search: %s", summarize(cs))
				}
			}
			assert.NotZero(t, upstreamSearches, "the upstream is searched")
		})
	}
}

func searchedArchs(cs []vulnerability.Criteria) []string {
	var out []string
	for _, c := range cs {
		if ac, ok := c.(*search.ArchitectureCriteria); ok {
			out = append(out, ac.Arch)
		}
	}
	return out
}

func summarize(cs []vulnerability.Criteria) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		if s, ok := c.(interface{ Summarize() string }); ok {
			parts[i] = s.Summarize()
		} else {
			parts[i] = fmt.Sprintf("%T", c)
		}
	}
	return strings.Join(parts, "; ")
}
