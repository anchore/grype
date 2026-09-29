package models

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

func Test_upgradesFor(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		fix      vulnerability.Fix
		expected vulnerability.Fix
	}{
		{
			name: "fix equal to the installed version is not an upgrade",
			pkg:  pkg.Package{Name: "rf-libc6", Version: "2.39-0ubuntu8.7"},
			fix: vulnerability.Fix{
				Versions: []string{"0:2.39-0ubuntu8.7"},
				State:    vulnerability.FixStateFixed,
			},
			expected: vulnerability.Fix{
				Versions: []string{},
				State:    vulnerability.FixStateNotFixed,
			},
		},
		{
			name: "fix older than the installed version is not an upgrade",
			pkg:  pkg.Package{Name: "rf-perl", Version: "5.38.2-5ubuntu0.1"},
			fix: vulnerability.Fix{
				Versions: []string{"0:5.38.2-3.2ubuntu0.4"},
				State:    vulnerability.FixStateFixed,
			},
			expected: vulnerability.Fix{
				Versions: []string{},
				State:    vulnerability.FixStateNotFixed,
			},
		},
		{
			name: "keeps the upgrades and drops the rest, preserving fixed state",
			pkg:  pkg.Package{Name: "rf-nginx", Version: "1.24.0-2ubuntu7.8"},
			fix: vulnerability.Fix{
				Versions: []string{"0:1.18.0-6ubuntu14.12", "0:1.24.0-2ubuntu7.13", "0:1.28.0-6ubuntu1.4"},
				State:    vulnerability.FixStateFixed,
				Available: []vulnerability.FixAvailable{
					{Version: "0:1.18.0-6ubuntu14.12"},
					{Version: "0:1.24.0-2ubuntu7.13"},
				},
			},
			expected: vulnerability.Fix{
				Versions: []string{"0:1.24.0-2ubuntu7.13", "0:1.28.0-6ubuntu1.4"},
				State:    vulnerability.FixStateFixed,
				Available: []vulnerability.FixAvailable{
					{Version: "0:1.24.0-2ubuntu7.13"},
				},
			},
		},
		{
			name: "untouched when every version is an upgrade",
			pkg:  pkg.Package{Name: "rf-libc6", Version: "2.39-0ubuntu8.7"},
			fix: vulnerability.Fix{
				Versions: []string{"0:2.39-0ubuntu8.8"},
				State:    vulnerability.FixStateFixed,
			},
			expected: vulnerability.Fix{
				Versions: []string{"0:2.39-0ubuntu8.8"},
				State:    vulnerability.FixStateFixed,
			},
		},
		{
			name: "an unparseable fix version is still reported",
			pkg:  pkg.Package{Name: "rf-thing", Version: "1.0"},
			fix: vulnerability.Fix{
				Versions: []string{"not-a-version"},
				State:    vulnerability.FixStateFixed,
			},
			expected: vulnerability.Fix{
				Versions: []string{"not-a-version"},
				State:    vulnerability.FixStateFixed,
			},
		},
		{
			name: "a not-fixed record is left alone",
			pkg:  pkg.Package{Name: "rf-libc6", Version: "2.39-0ubuntu8.7"},
			fix: vulnerability.Fix{
				State: vulnerability.FixStateNotFixed,
			},
			expected: vulnerability.Fix{
				State: vulnerability.FixStateNotFixed,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := upgradesFor(tt.fix, tt.pkg, version.DebFormat)
			require.Equal(t, tt.expected, got)
		})
	}
}

func Test_upgradesFor_doesNotMutateTheRecord(t *testing.T) {
	fix := vulnerability.Fix{
		Versions: []string{"0:1.18.0-6ubuntu14.12", "0:1.24.0-2ubuntu7.13"},
		State:    vulnerability.FixStateFixed,
	}
	p := pkg.Package{Name: "rf-nginx", Version: "1.24.0-2ubuntu7.8"}

	_ = upgradesFor(fix, p, version.DebFormat)

	require.Equal(t, []string{"0:1.18.0-6ubuntu14.12", "0:1.24.0-2ubuntu7.13"}, fix.Versions)
}
