package java

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherJava_matchUpstreamMavenPackage(t *testing.T) {
	matcher := Matcher{}
	p := pkg.Package{
		ID:           pkg.ID(uuid.NewString()),
		Name:         "spring-webmvc",
		Version:      "5.1.5.RELEASE",
		Type:         syftPkg.JavaPkg,
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			ArchiveDigests: []pkg.Digest{
				{
					Algorithm: "sha1",
					Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
				},
			},
		},
	}

	store := newMockProvider()
	actual, _ := matcher.matchUpstreamMavenPackages(store, p)

	assert.Len(t, actual, 2, "unexpected indirect matches count")

}
