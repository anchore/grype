package internal

import (
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/require"
)

func TestMatchPackageByCPEs_CPythonVersionOrdering(t *testing.T) {
	for _, vendor := range []string{"python", "python_software_foundation"} {
		for _, packageType := range []syftPkg.Type{syftPkg.BinaryPkg, syftPkg.ApkPkg} {
			for _, tt := range []struct {
				v        string
				affected bool
			}{
				{"3.14.8", true}, {"3.15.0a5", true}, {"3.15.0a6", false},
				{"3.15.0b1", false}, {"3.15.0rc3", false}, {"3.15.0", false}, {"3.15.1", false},
			} {
				t.Run(fmt.Sprintf("%s/%s/%s", vendor, packageType, tt.v), func(t *testing.T) {
					// CVE-2025-15367's CNA uses Python ordering for this prerelease boundary.
					// Its NVD CPE bound has no version format.
					store := mock.VulnerabilityProvider(vulnerability.Vulnerability{
						Reference:   vulnerability.Reference{ID: "CVE-2025-15367", Namespace: "nvd:cpe"},
						PackageName: "python", Constraint: version.MustGetConstraint("< 3.15.0a6", version.UnknownFormat),
						CPEs: []cpe.CPE{cpe.Must(fmt.Sprintf("cpe:2.3:a:%s:python:*:*:*:*:*:*:*:*", vendor), "")},
					})
					packageVersion := tt.v
					if packageType == syftPkg.ApkPkg {
						packageVersion += "-r0"
					}
					p := pkg.Package{Name: "python3", Version: packageVersion, Type: packageType,
						CPEs: []cpe.CPE{cpe.Must(fmt.Sprintf("cpe:2.3:a:%s:python:%s:*:*:*:*:*:*:*", vendor, packageVersion), "")},
					}
					matches, _, err := MatchPackageByCPEs(store, p, match.StockMatcher)
					require.NoError(t, err)
					if tt.affected {
						require.Len(t, matches, 1)
					} else {
						require.Empty(t, matches)
					}
				})
			}
		}
	}
}

func TestMatchPackageByCPEs_OpenSSLLetterVersions(t *testing.T) {
	store := mock.VulnerabilityProvider(vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: "CVE-openssl-ordering", Namespace: "nvd:cpe"},
		PackageName: "openssl", Constraint: version.MustGetConstraint("< 1.0.2l", version.UnknownFormat),
		CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "")},
	})
	for _, tt := range []struct {
		v        string
		affected bool
	}{{"1.0.2", true}, {"1.0.2k", true}, {"1.0.2l", false}, {"1.0.2m", false}} {
		t.Run(tt.v, func(t *testing.T) {
			p := pkg.Package{Name: "openssl", Version: tt.v, Type: syftPkg.BinaryPkg,
				CPEs: []cpe.CPE{cpe.Must(fmt.Sprintf("cpe:2.3:a:openssl:openssl:%s:*:*:*:*:*:*:*", tt.v), "")}}
			matches, _, err := MatchPackageByCPEs(store, p, match.StockMatcher)
			require.NoError(t, err)
			if tt.affected {
				require.Len(t, matches, 1)
			} else {
				require.Empty(t, matches)
			}
		})
	}
}

func TestMatchPackageByCPEs_CPythonDistroVersionFallback(t *testing.T) {
	for _, tt := range []struct {
		name, v     string
		packageType syftPkg.Type
	}{
		{"deb revision", "3.14.8-1+deb13u1", syftPkg.DebPkg},
		{"rpm release", "3.14.8-2.el10", syftPkg.RpmPkg},
		{"apk epoch", "1:3.14.8-r0", syftPkg.ApkPkg},
		{"deb epoch", "1:3.14.8-1+deb13u1", syftPkg.DebPkg},
		{"unparseable", "not-a-version", syftPkg.BinaryPkg},
	} {
		t.Run(tt.name, func(t *testing.T) {
			counts := []int{}
			errs := []error{}
			// The unrecognized vendor is a control for the existing package comparator.
			for _, vendor := range []string{"example", "python"} {
				store := mock.VulnerabilityProvider(vulnerability.Vulnerability{
					Reference:   vulnerability.Reference{ID: "CVE-2025-15367", Namespace: "nvd:cpe"},
					PackageName: "python", Constraint: version.MustGetConstraint("< 3.15.0a6", version.UnknownFormat),
					CPEs: []cpe.CPE{cpe.Must(fmt.Sprintf("cpe:2.3:a:%s:python:*:*:*:*:*:*:*:*", vendor), "")},
				})
				p := pkg.Package{Name: "python3", Version: tt.v, Type: tt.packageType,
					CPEs: []cpe.CPE{cpe.Must(fmt.Sprintf("cpe:2.3:a:%s:python:*:*:*:*:*:*:*:*", vendor), "")}}
				matches, _, err := MatchPackageByCPEs(store, p, match.StockMatcher)
				counts = append(counts, len(matches))
				errs = append(errs, err)
			}
			require.Equal(t, errs[0] != nil, errs[1] != nil, "do not hide comparison errors")
			require.Equal(t, counts[0], counts[1], "preserve existing distro fallback results")
		})
	}
}

func TestMatchPackageByCPEs_CPythonVendorScope(t *testing.T) {
	for _, tt := range []struct{ part, vendor, product string }{
		{"a", "unrelated", "python"}, {"a", "python", "unrelated"}, {"o", "python", "python"},
	} {
		t.Run(fmt.Sprintf("%s/%s/%s", tt.part, tt.vendor, tt.product), func(t *testing.T) {
			c := cpe.Must(fmt.Sprintf("cpe:2.3:%s:%s:%s:*:*:*:*:*:*:*:*", tt.part, tt.vendor, tt.product), "")
			store := mock.VulnerabilityProvider(vulnerability.Vulnerability{
				Reference:   vulnerability.Reference{ID: "CVE-generic-ordering", Namespace: "nvd:cpe"},
				PackageName: tt.product, Constraint: version.MustGetConstraint("< 3.15.0a6", version.UnknownFormat), CPEs: []cpe.CPE{c},
			})
			p := pkg.Package{Name: tt.product, Version: "3.15.0", Type: syftPkg.BinaryPkg, CPEs: []cpe.CPE{c}}
			matches, _, err := MatchPackageByCPEs(store, p, match.StockMatcher)
			require.NoError(t, err)
			require.Len(t, matches, 1, "do not change other products' generic letter ordering")
		})
	}
}

func TestMatchPackageByCPEs_CPythonExplicitUpdate(t *testing.T) {
	for _, update := range []string{"alpha5", "a5", "beta1", "rc3"} {
		t.Run(update, func(t *testing.T) {
			// A CPython CPE may split a prerelease across version and update.
			// Do not interpret only the version as a final release and hide a match.
			c := cpe.Must(fmt.Sprintf("cpe:2.3:a:python:python:3.15.0:%s:*:*:*:*:*:*", update), "")
			store := mock.VulnerabilityProvider(vulnerability.Vulnerability{
				Reference:   vulnerability.Reference{ID: "CVE-2025-15367", Namespace: "nvd:cpe"},
				PackageName: "python", Constraint: version.MustGetConstraint("< 3.15.0a6", version.UnknownFormat), CPEs: []cpe.CPE{c},
			})
			p := pkg.Package{Name: "python", Version: "3.15.0", Type: syftPkg.BinaryPkg, CPEs: []cpe.CPE{c}}
			matches, _, err := MatchPackageByCPEs(store, p, match.StockMatcher)
			require.NoError(t, err)
			require.Len(t, matches, 1, "keep the existing comparison until update normalization is implemented")
		})
	}
}
