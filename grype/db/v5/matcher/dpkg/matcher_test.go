package dpkg

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/stringutil"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherDpkg_matchBySourceIndirection(t *testing.T) {
	matcher := Matcher{}

	d, err := distro.New(distro.Debian, "8", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "neutron",
		Version: "2014.1.3-6",
		Type:    syftPkg.DebPkg,
		Distro:  d,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "neutron-devel",
			},
		},
	}

	vp := newMockProvider()
	actual, err := matcher.matchUpstreamPackages(vp, p)
	assert.NoError(t, err, "unexpected err from matchUpstreamPackages", err)

	assert.Len(t, actual, 2, "unexpected indirect matches count")

	foundCVEs := stringutil.NewStringSet()
	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		require.NotEmpty(t, a.Details)
		for _, d := range a.Details {
			assert.Equal(t, match.ExactIndirectMatch, d.Type, "indirect match not indicated")
		}
		assert.Equal(t, p.Name, a.Package.Name, "failed to capture original package name")
		for _, detail := range a.Details {
			assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
		}
	}

	for _, id := range []string{"CVE-2014-fake-2", "CVE-2013-fake-3"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}
	if t.Failed() {
		t.Logf("discovered CVES: %+v", foundCVEs)
	}
}
