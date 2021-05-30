package rpmdb

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherDpkg_matchBySourceIndirection(t *testing.T) {
	matcher := Matcher{}
	p := pkg.Package{
		Name:    "neutron-libs",
		Version: "7.1.3-6",
		Type:    syftPkg.RpmPkg,
		Metadata: pkg.RpmdbMetadata{
			SourceRpm: "neutron-7.1.3-6.el8.src.rpm",
		},
	}

	d, err := distro.NewDistro(distro.CentOS, "8", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	store := newMockProvider()
	actual, err := matcher.matchBySourceIndirection(store, &d, p)

	assert.Len(t, actual, 2, "unexpected indirect matches count")

	foundCVEs := internal.NewStringSet()

	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		assert.Equal(t, match.ExactIndirectMatch, a.Type, "indirect match not indicated")
		assert.Equal(t, p.Name, a.Package.Name, "failed to capture original package name")
		for _, detail := range a.MatchDetails {
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

func TestMatcherDpkg_matchBySourceIndirection_ignoreSource(t *testing.T) {
	matcher := Matcher{}
	p := pkg.Package{
		Name:    "neutron",
		Version: "7.1.3-6",
		Type:    syftPkg.RpmPkg,
		Metadata: pkg.RpmdbMetadata{
			// this ends up being the same matches as the original package, thus should be ignored
			SourceRpm: "neutron-7.1.3-6.el8.src.rpm",
		},
	}

	d, err := distro.NewDistro(distro.CentOS, "8", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	store := newMockProvider()
	actual, err := matcher.matchBySourceIndirection(store, &d, p)

	assert.Len(t, actual, 0, "unexpected indirect matches count")
}
