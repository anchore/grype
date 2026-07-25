package rust

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcher_CargoLockSource(t *testing.T) {
	provider := mock.VulnerabilityProvider(vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-hpcx-3pw8-g3j2",
			Namespace: "github:language:rust",
		},
		PackageName: "telemetry",
		Constraint:  version.MustGetConstraint("< 0.1.3", version.UnknownFormat),
	})
	matcher := NewRustMatcher(MatcherConfig{})

	tests := []struct {
		name        string
		source      *string
		wantMatches int
	}{
		{
			name:        "crates.io package is matched",
			source:      ptr("registry+https://github.com/rust-lang/crates.io-index"),
			wantMatches: 1,
		},
		{
			name:        "git package is matched",
			source:      ptr("git+https://github.com/example/telemetry?rev=0123456789abcdef#0123456789abcdef"),
			wantMatches: 1,
		},
		{
			name:        "local path package is not matched",
			source:      ptr(""),
			wantMatches: 0,
		},
		{
			name:        "package without Cargo.lock metadata preserves legacy matching",
			wantMatches: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syftPackage := syftPkg.Package{
				Name:     "telemetry",
				Version:  "0.1.0",
				Language: syftPkg.Rust,
				Type:     syftPkg.RustPkg,
			}
			if tt.source != nil {
				syftPackage.Metadata = syftPkg.RustCargoLockEntry{
					Name:    syftPackage.Name,
					Version: syftPackage.Version,
					Source:  *tt.source,
				}
			}
			p := pkg.New(syftPackage)

			matches, ignores, err := matcher.Match(provider, p)
			require.NoError(t, err)
			require.Empty(t, ignores)
			require.Len(t, matches, tt.wantMatches)
		})
	}
}

func TestMatcher_LocalCargoPackagePreservesOptInCPEMatching(t *testing.T) {
	provider := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "GHSA-hpcx-3pw8-g3j2",
				Namespace: "github:language:rust",
			},
			PackageName: "telemetry",
			Constraint:  version.MustGetConstraint("< 0.1.3", version.UnknownFormat),
		},
		vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-2099-0001",
				Namespace: "nvd:cpe",
			},
			PackageName: "telemetry",
			Constraint:  version.MustGetConstraint("< 0.2.0", version.UnknownFormat),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:example:telemetry:*:*:*:*:*:*:*:*", ""),
			},
		},
	)
	syftPackage := syftPkg.Package{
		Name:     "telemetry",
		Version:  "0.1.0",
		Language: syftPkg.Rust,
		Type:     syftPkg.RustPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:example:telemetry:0.1.0:*:*:*:*:*:*:*", ""),
		},
		Metadata: syftPkg.RustCargoLockEntry{
			Name:    "telemetry",
			Version: "0.1.0",
		},
	}

	matches, ignores, err := NewRustMatcher(MatcherConfig{UseCPEs: true}).Match(provider, pkg.New(syftPackage))
	require.NoError(t, err)
	require.Empty(t, ignores)
	require.Len(t, matches, 1)
	require.Equal(t, "CVE-2099-0001", matches[0].Vulnerability.ID)
	require.Len(t, matches[0].Details, 1)
	require.Equal(t, match.CPEMatch, matches[0].Details[0].Type)
}

func TestMatcher_RustBinaryAuditPackagePreservesMatching(t *testing.T) {
	provider := mock.VulnerabilityProvider(vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-hpcx-3pw8-g3j2",
			Namespace: "github:language:rust",
		},
		PackageName: "telemetry",
		Constraint:  version.MustGetConstraint("< 0.1.3", version.UnknownFormat),
	})
	syftPackage := syftPkg.Package{
		Name:     "telemetry",
		Version:  "0.1.0",
		Language: syftPkg.Rust,
		Type:     syftPkg.RustPkg,
		Metadata: syftPkg.RustBinaryAuditEntry{
			Name:    "telemetry",
			Version: "0.1.0",
		},
	}

	matches, ignores, err := NewRustMatcher(MatcherConfig{}).Match(provider, pkg.New(syftPackage))
	require.NoError(t, err)
	require.Empty(t, ignores)
	require.Len(t, matches, 1)
	require.Equal(t, "GHSA-hpcx-3pw8-g3j2", matches[0].Vulnerability.ID)
}

func ptr[T any](value T) *T {
	return &value
}
