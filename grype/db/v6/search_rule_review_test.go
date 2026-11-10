package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// R37 (review of #3751): the built-in el/amzn `add` rule also fires for a build of the image's own
// release, adding a search of a channel that by the rule's own comment holds no rows (the release's own
// builds are channel-less). Every native rpm on a RapidFort image pays for that search, and an agreed
// "warn when a remapped distro resolves no OS rows" would fire for each one. A build for another
// release is the case the rule exists for and keeps its search.
func TestReview_R37_OwnReleaseBuildAddsNoEmptyChannelSearch(t *testing.T) {
	vp := rulesProvider(KnownSearchRules()...)
	rpm := syftPkg.RpmPkg
	rfRedhat9 := *distro.New(distro.RapidFortRedHat, "9", "")
	rfAmazon := *distro.New(distro.RapidFortAmazonLinux, "2023", "")

	// every native build also searches the base distro, which this test is not about
	rhel9 := ruled("redhat@9+", "curl", -10)

	tests := []struct {
		name    string
		pkgName string
		version string
		d       distro.Distro
		want    []searched
	}{
		{
			name:    "control: an el10 build on a RHEL 9 image adds the el10 channel",
			want:    []searched{own("rapidfort-redhat@9+", "curl"), ruled("rapidfort-redhat@9+el10", "curl", 20), rhel9},
			pkgName: "curl", version: "8.12.1-1.el10", d: rfRedhat9,
		},
		{
			name:    "an el9 build on a RHEL 9 image searches only its own channel-less rows",
			want:    []searched{own("rapidfort-redhat@9+", "curl"), rhel9},
			pkgName: "curl", version: "7.76.1-29.el9", d: rfRedhat9,
		},
		{
			name:    "an el9_4 build on a RHEL 9 image searches only its own channel-less rows",
			want:    []searched{own("rapidfort-redhat@9+", "curl"), rhel9},
			pkgName: "curl", version: "7.76.1-29.el9_4.1", d: rfRedhat9,
		},
		{
			name:    "an amzn2023 build on an Amazon Linux 2023 image searches only its own channel-less rows",
			want:    []searched{own("rapidfort-amazonlinux@2023+", "7zip"), ruled("amazonlinux@2023+", "7zip", -10)},
			pkgName: "7zip", version: "26.01-14.amzn2023.0.1", d: rfAmazon,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := searchOf(tt.pkgName, tt.version, tt.d, rpm)
			assert.ElementsMatch(t, tt.want, searchesOf(rewrites(vp, p, nameSearch(p))))
		})
	}
}
