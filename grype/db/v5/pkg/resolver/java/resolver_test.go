package java

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	grypePkg "github.com/anchore/grype/grype/pkg"
)

func TestResolver_Normalize(t *testing.T) {
	tests := []struct {
		name       string
		normalized string
	}{
		{
			name:       "PyYAML",
			normalized: "pyyaml",
		},
		{
			name:       "oslo.concurrency",
			normalized: "oslo.concurrency",
		},
		{
			name:       "",
			normalized: "",
		},
		{
			name:       "test---1",
			normalized: "test---1",
		},
		{
			name:       "AbCd.-__.--.-___.__.--1234____----....XyZZZ",
			normalized: "abcd.-__.--.-___.__.--1234____----....xyzzz",
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolvedNames := resolver.Normalize(test.name)
			assert.Equal(t, resolvedNames, test.normalized)
		})
	}
}

func TestResolver_Resolve(t *testing.T) {
	tests := []struct {
		name     string
		pkg      grypePkg.Package
		resolved []string
	}{
		{
			name: "both artifact and manifest 1",
			pkg: grypePkg.Package{
				Name:     "ABCD",
				Version:  "1.2.3.4",
				Language: "java",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath:   "virtual-path-info",
					PomArtifactID: "pom-ARTIFACT-ID-info",
					PomGroupID:    "pom-group-ID-info",
					ManifestName:  "main-section-name-info",
				},
			},
			resolved: []string{"pom-group-id-info:pom-artifact-id-info", "pom-group-id-info:main-section-name-info"},
		},
		{
			name: "both artifact and manifest 2",
			pkg: grypePkg.Package{
				ID:   grypePkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
					ManifestName:  "man-name",
				},
			},
			resolved: []string{
				"g-id:art-id",
				"g-id:man-name",
			},
		},
		{
			name: "no group id",
			pkg: grypePkg.Package{
				ID:   grypePkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					ManifestName:  "man-name",
				},
			},
			resolved: []string{},
		},
		{
			name: "only manifest",
			pkg: grypePkg.Package{
				ID:   grypePkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath:  "v-path",
					PomGroupID:   "g-id",
					ManifestName: "man-name",
				},
			},
			resolved: []string{
				"g-id:man-name",
			},
		},
		{
			name: "only artifact",
			pkg: grypePkg.Package{
				ID:   grypePkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
				},
			},
			resolved: []string{
				"g-id:art-id",
			},
		},
		{
			name: "no artifact or manifest",
			pkg: grypePkg.Package{
				ID:   grypePkg.ID(uuid.NewString()),
				Name: "a-name",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath: "v-path",
					PomGroupID:  "g-id",
				},
			},
			resolved: []string{},
		},
		{
			name: "with valid purl",
			pkg: grypePkg.Package{
				ID:   grypePkg.ID(uuid.NewString()),
				Name: "a-name",
				PURL: "pkg:maven/org.anchore/b-name@0.2",
			},
			resolved: []string{"org.anchore:b-name"},
		},
		{
			name: "ignore invalid pURLs",
			pkg: grypePkg.Package{
				ID:   grypePkg.ID(uuid.NewString()),
				Name: "a-name",
				PURL: "pkg:BAD/",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath:   "v-path",
					PomArtifactID: "art-id",
					PomGroupID:    "g-id",
				},
			},
			resolved: []string{
				"g-id:art-id",
			},
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolvedNames := resolver.Resolve(test.pkg)
			assert.ElementsMatch(t, resolvedNames, test.resolved)
		})
	}
}
