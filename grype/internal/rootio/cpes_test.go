package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestEquivalentCPEs locks in that for a rootio-prefixed package, the
// synthesizer returns the upstream-name-derived CPEs as additions (deduped
// against the caller's existing list), and returns nil for non-rootio
// packages or rootio packages whose bare form equals the prefixed form.
//
// This is the CPE-side counterpart of the resolver name fanout: without it,
// syft's rootio-prefixed CPEs (e.g. `rootio:rootio-openssh`) never align
// with NVD's canonical-vendor CPEs (`openbsd:openssh`) and the NVD-CPE
// matching path stays dark on rootio packages.
func TestEquivalentCPEs(t *testing.T) {
	mustCPE := func(s string) cpe.CPE {
		c, err := cpe.New(s, "")
		assert.NoError(t, err)
		return c
	}

	tests := []struct {
		name        string
		syftPkg     syftPkg.Package
		javaGroupID string
		// CPE strings we expect to appear in the returned additions list
		expectAdded []string
		// when true, expect EquivalentCPEs to return nil (no additions)
		expectNil bool
		// when set, expect the returned additions list to have at least this length
		expectMinAdditions int
	}{
		{
			name: "rootio-prefixed apk yields upstream-named CPE addition",
			syftPkg: syftPkg.Package{
				Name:    "rootio-openssh",
				Version: "9.3_p2-r20074",
				Type:    syftPkg.ApkPkg,
				CPEs: []cpe.CPE{
					mustCPE("cpe:2.3:a:rootio-openssh:rootio-openssh:9.3_p2-r20074:*:*:*:*:*:*:*"),
				},
			},
			expectAdded: []string{"cpe:2.3:a:openssh:openssh:9.3_p2-r20074:*:*:*:*:*:*:*"},
		},
		{
			name: "upstream-named deb (version-side rootio token) — StripPrefix is no-op so no additions",
			syftPkg: syftPkg.Package{
				Name:    "libgcrypt20",
				Version: "1.10.1-3.root.io.2",
				Type:    syftPkg.DebPkg,
				CPEs:    []cpe.CPE{mustCPE("cpe:2.3:a:libgcrypt20:libgcrypt20:1.10.1-3.root.io.2:*:*:*:*:*:*:*")},
			},
			expectNil: true,
		},
		{
			name: "@rootio scoped npm yields bare-named CPE addition",
			syftPkg: syftPkg.Package{
				Name:    "@rootio/semver",
				Version: "5.7.1-root.io.1",
				Type:    syftPkg.NpmPkg,
				CPEs:    []cpe.CPE{mustCPE("cpe:2.3:a:rootio:semver:5.7.1-root.io.1:*:*:*:*:*:*:*")},
			},
			expectAdded: []string{"cpe:2.3:a:semver:semver:5.7.1-root.io.1:*:*:*:*:*:*:*"},
		},
		{
			name: "non-rootio package returns no additions",
			syftPkg: syftPkg.Package{
				Name: "openssh", Version: "9.6_p1-r0", Type: syftPkg.ApkPkg,
				CPEs: []cpe.CPE{mustCPE("cpe:2.3:a:openssh:openssh:9.6_p1-r0:*:*:*:*:*:*:*")},
			},
			expectNil: true,
		},
		{
			// For Java the rootio marker lives on the groupID, while syft emits the
			// artifactID alone in p.Name. StripPrefix on the artifactID is a no-op
			// (artifactIDs aren't `io.root.`-prefixed), so the CPE fan-out for Java
			// is structurally a no-op even when IsPackage returns true. Stock
			// artifactID-based CPEs already align with NVD's vendor:product space.
			name: "java with io.root.* groupID: StripPrefix on artifactID is a no-op so no additions",
			syftPkg: syftPkg.Package{
				Name: "commons-collections", Version: "3.2.2", Type: syftPkg.JavaPkg,
				CPEs: []cpe.CPE{},
			},
			javaGroupID: "io.root.commons-collections",
			expectNil:   true,
		},
		{
			// The hand-built "group:artifact" name form does carry the io.root. prefix on
			// p.Name, so StripPrefix yields a stripped name and the synthesizer runs.
			name: "java with io.root.* on p.Name (legacy hand-built form) yields additions",
			syftPkg: syftPkg.Package{
				Name: "io.root.commons-collections:commons-collections", Version: "3.2.2", Type: syftPkg.JavaPkg,
				CPEs: []cpe.CPE{},
			},
			expectMinAdditions: 1,
		},
		{
			name: "dedupe: existing list already contains the upstream form, so no additions",
			syftPkg: syftPkg.Package{
				Name:    "rootio-openssh",
				Version: "9.3_p2-r20074",
				Type:    syftPkg.ApkPkg,
				CPEs: []cpe.CPE{
					mustCPE("cpe:2.3:a:rootio-openssh:rootio-openssh:9.3_p2-r20074:*:*:*:*:*:*:*"),
					mustCPE("cpe:2.3:a:openssh:openssh:9.3_p2-r20074:*:*:*:*:*:*:*"),
				},
			},
			expectNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			additions := EquivalentCPEs(tt.syftPkg, tt.javaGroupID, tt.syftPkg.CPEs)
			if tt.expectNil {
				assert.Nil(t, additions, "expected no additions for this case")
				return
			}
			if tt.expectMinAdditions > 0 {
				assert.GreaterOrEqual(t, len(additions), tt.expectMinAdditions, "expected at least %d additions", tt.expectMinAdditions)
			}
			if len(tt.expectAdded) > 0 {
				got := make(map[string]bool)
				for _, c := range additions {
					got[c.Attributes.BindToFmtString()] = true
				}
				for _, expected := range tt.expectAdded {
					assert.True(t, got[expected], "expected additions to contain %q; got %v", expected, got)
				}
			}
		})
	}
}
