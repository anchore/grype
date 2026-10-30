package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
)

func TestPackageNameFromPURL(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want string
	}{
		{
			// A Go module is identified by its full path; the namespace is the
			// leading part of it rather than metadata, so dropping it filed the
			// statement under a different package than the advisory and matcher
			// paths use.
			name: "golang module keeps its namespace",
			purl: "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
			want: "github.com/gin-gonic/gin",
		},
		{
			name: "golang module on a vanity host",
			purl: "pkg:golang/k8s.io/client-go@v0.29.0",
			want: "k8s.io/client-go",
		},
		{
			name: "golang module with a version suffix in the name",
			purl: "pkg:golang/gopkg.in/yaml.v3@v3.0.1",
			want: "gopkg.in/yaml.v3",
		},
		{
			name: "golang module with no namespace is unchanged",
			purl: "pkg:golang/stdlib@1.21.0",
			want: "stdlib",
		},
		{
			name: "composer keeps the vendor",
			purl: "pkg:composer/craftcms/cms@5.10.6",
			want: "craftcms/cms",
		},
		{
			name: "maven keeps the groupId separator",
			purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			want: "org.apache.commons:commons-lang3",
		},
		{
			name: "npm scoped name is rejoined",
			purl: "pkg:npm/%40angular/core@17.0.0",
			want: "@angular/core",
		},
		{
			// An ecosystem whose namespace is metadata rather than identity is
			// left alone, so this change does not widen beyond Go.
			name: "namespace that is not part of the name is dropped",
			purl: "pkg:deb/debian/curl@7.50.3-1",
			want: "curl",
		},
		{
			name: "flat ecosystem is unchanged",
			purl: "pkg:pypi/urllib3@1.26.16",
			want: "urllib3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purl, err := packageurl.FromString(tt.purl)
			require.NoError(t, err)

			require.Equal(t, tt.want, PackageNameFromPURL(&purl))
		})
	}
}
