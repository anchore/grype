package portage

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/stringutil"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherPortage_Match(t *testing.T) {
	matcher := Matcher{}

	d, err := distro.New(distro.Gentoo, "", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "app-misc/neutron",
		Version: "2014.1.3",
		Type:    syftPkg.PortagePkg,
		Distro:  d,
	}

	store := newMockProvider()
	actual, _, err := matcher.Match(store, p)
	assert.NoError(t, err, "unexpected err from Match", err)

	assert.Len(t, actual, 1, "unexpected indirect matches count")

	foundCVEs := stringutil.NewStringSet()
	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		require.NotEmpty(t, a.Details)
		assert.Equal(t, p.Name, a.Package.Name, "failed to capture original package name")
		for _, detail := range a.Details {
			assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
		}
	}

	for _, id := range []string{"CVE-2014-fake-2"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}
	if t.Failed() {
		t.Logf("discovered CVES: %+v", foundCVEs)
	}
}
