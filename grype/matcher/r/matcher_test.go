package r

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/grype/internal/stringutil"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherType(t *testing.T) {
	m := NewRMatcher(MatcherConfig{})
	assert.Equal(t, match.RMatcher, m.Type())
}

func TestMatcherPackageTypes(t *testing.T) {
	m := NewRMatcher(MatcherConfig{})
	assert.Equal(t, []syftPkg.Type{syftPkg.Rpkg}, m.PackageTypes())
}

func newMockProvider() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "RSEC-2023-1",
				Namespace: "rsec:language:R",
			},
			PackageName: "jsonlite",
			Constraint:  version.MustGetConstraint(">=0.9.12,<1.8.8", version.UnknownFormat),
		},
		{
			Reference: vulnerability.Reference{
				ID:        "RSEC-2023-2",
				Namespace: "rsec:language:R",
			},
			PackageName: "commonmark",
			Constraint:  version.MustGetConstraint(">=0.2,<1.9.2", version.UnknownFormat),
		},
		{
			Reference: vulnerability.Reference{
				ID:        "RSEC-2023-3",
				Namespace: "rsec:language:R",
			},
			PackageName: "commonmark",
			Constraint:  version.MustGetConstraint(">=0.2,<1.8", version.UnknownFormat),
		},
		{
			Reference: vulnerability.Reference{
				ID:        "RSEC-2023-4",
				Namespace: "rsec:language:R",
			},
			PackageName: "gdata",
			Constraint:  version.MustGetConstraint(">=2.16.1,<3.0.0", version.UnknownFormat),
		},
	}...)
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name         string
		pkg          pkg.Package
		expectedCVEs []string
	}{
		{
			name: "vulnerable jsonlite version",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "jsonlite",
				Version:  "1.7.0",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{"RSEC-2023-1"},
		},
		{
			name: "fixed jsonlite version - no match",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "jsonlite",
				Version:  "2.0.0",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{},
		},
		{
			name: "commonmark matches multiple vulnerabilities",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "commonmark",
				Version:  "1.7.0",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{"RSEC-2023-2", "RSEC-2023-3"},
		},
		{
			name: "commonmark fixed for one CVE but not another",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "commonmark",
				Version:  "1.8.1",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{"RSEC-2023-2"},
		},
		{
			name: "gdata at fixed version - no match",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "gdata",
				Version:  "3.0.0",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{},
		},
		{
			name: "gdata vulnerable version",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "gdata",
				Version:  "2.18.0",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{"RSEC-2023-4"},
		},
		{
			name: "unknown version - no match",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "jsonlite",
				Version:  "unknown",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{},
		},
		{
			name: "package not in database - no match",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "ggplot2",
				Version:  "3.4.0",
				Language: syftPkg.R,
				Type:     syftPkg.Rpkg,
			},
			expectedCVEs: []string{},
		},
	}

	store := newMockProvider()
	matcher := NewRMatcher(MatcherConfig{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, _, err := matcher.Match(store, tt.pkg)
			require.NoError(t, err)

			foundCVEs := stringutil.NewStringSet()
			for _, m := range matches {
				foundCVEs.Add(m.Vulnerability.ID)

				require.NotEmpty(t, m.Details)
				assert.Equal(t, tt.pkg.Name, m.Package.Name)
				for _, detail := range m.Details {
					assert.Equal(t, matcher.Type(), detail.Matcher)
				}
			}

			assert.Equal(t, len(tt.expectedCVEs), len(matches), "unexpected match count")
			for _, expectedCVE := range tt.expectedCVEs {
				assert.True(t, foundCVEs.Contains(expectedCVE), "missing expected CVE: %s", expectedCVE)
			}
		})
	}
}

func TestMatchWithConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  MatcherConfig
		wantErr bool
	}{
		{
			name:    "default config",
			config:  MatcherConfig{},
			wantErr: false,
		},
		{
			name:    "with CPEs enabled",
			config:  MatcherConfig{UseCPEs: true},
			wantErr: false,
		},
		{
			name:    "with CPEs disabled",
			config:  MatcherConfig{UseCPEs: false},
			wantErr: false,
		},
	}

	store := newMockProvider()
	pkg := pkg.Package{
		ID:       pkg.ID(uuid.NewString()),
		Name:     "jsonlite",
		Version:  "1.7.0",
		Language: syftPkg.R,
		Type:     syftPkg.Rpkg,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewRMatcher(tt.config)
			_, _, err := matcher.Match(store, pkg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
