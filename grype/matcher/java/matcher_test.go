package java

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// springPackage builds a Java package fixture for org.springframework:
// spring-webmvc 5.3.20 with the supplied PomArtifactID/PomGroupID. Both
// 5.3-range GHSAs in the spring-webmvc fixture cover this version.
func springPackage(metadata pkg.JavaMetadata) pkg.Package {
	return dbtest.NewPackage("org.springframework.spring-webmvc", "5.3.20", syftPkg.JavaPkg).
		WithLanguage(syftPkg.Java).
		WithMetadata(metadata).
		Build()
}

// TestMatcherJava_matchUpstreamMavenPackage exercises the
// SearchMavenUpstream branch of the matcher. The maven HTTP adapter is
// mocked (mockMavenSearcher) because the test suite must not hit
// search.maven.org; the live-API equivalent lives in
// matcher_integration_test.go behind the api_limits build tag. The
// vulnerability data is real, sourced from the spring-webmvc fixture.
func TestMatcherJava_matchUpstreamMavenPackage(t *testing.T) {
	newMatcher := func(searcher MavenSearcher) *Matcher {
		return &Matcher{
			cfg: MatcherConfig{
				ExternalSearchConfig: ExternalSearchConfig{
					SearchMavenUpstream: true,
				},
			},
			MavenSearcher: searcher,
		}
	}

	cases := []struct {
		name string
		// the package the SBOM claims to have
		input pkg.Package
		// what the (mocked) Maven search would return for the same SHA;
		// for cases that don't trigger a Maven lookup this is unused.
		mavenLookup pkg.Package
		// real-data behavior: when a Java package has neither pom
		// metadata nor a PURL, name.JavaResolver yields no search names
		// and the v6 DB cannot resolve a match. The original mock-based
		// test silently fell back to the literal pkg.Name field, masking
		// this. The migrated test surfaces it.
		expectMatches bool
	}{
		{
			name: "do not search maven - metadata present",
			input: springPackage(pkg.JavaMetadata{
				PomArtifactID: "spring-webmvc",
				PomGroupID:    "org.springframework",
				ArchiveDigests: []pkg.Digest{
					{Algorithm: "sha1", Value: "236e3bfdbdc6c86629237a74f0f11414adb4e211"},
				},
			}),
			expectMatches: true,
		},
		{
			name: "search maven - missing pom metadata, sha1 present",
			input: springPackage(pkg.JavaMetadata{
				ArchiveDigests: []pkg.Digest{
					{Algorithm: "sha1", Value: "236e3bfdbdc6c86629237a74f0f11414adb4e211"},
				},
			}),
			// search.maven.org returns the resolved package, which we
			// simulate as the same spring-webmvc 5.3.20 record so the
			// downstream match path is independent of the network.
			mavenLookup: springPackage(pkg.JavaMetadata{
				PomArtifactID: "spring-webmvc",
				PomGroupID:    "org.springframework",
			}),
			expectMatches: true,
		},
		{
			name: "search maven flagged but no sha1 - direct match has no resolvable identifier",
			input: springPackage(pkg.JavaMetadata{
				ArchiveDigests: []pkg.Digest{
					{Algorithm: "sha1", Value: ""},
				},
			}),
			expectMatches: false,
		},
	}

	dbtest.DBs(t, "spring-webmvc").
		Run(func(t *testing.T, db *dbtest.DB) {
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					searcher := mockMavenSearcher{pkg: c.mavenLookup}
					matcher := newMatcher(searcher)

					actual, _, err := matcher.matchUpstreamMavenPackages(db, c.input)
					require.NoError(t, err)

					if !c.expectMatches {
						assert.Empty(t, actual, "expected no matches when no resolvable identifier is available")
						return
					}

					require.Len(t, actual, 2, "expected 2 spring-webmvc GHSAs to match")
					seenIDs := make(map[string]bool)
					for _, m := range actual {
						seenIDs[m.Vulnerability.ID] = true
						require.NotEmpty(t, m.Details)
						for _, d := range m.Details {
							assert.Equal(t, match.ExactIndirectMatch, d.Type, "indirect match expected")
							assert.Equal(t, matcher.Type(), d.Matcher, "matcher type recorded")
						}
						assert.Equal(t, c.input.Name, m.Package.Name, "match should reference the SBOM package")
					}
					for _, id := range []string{"GHSA-7phw-cxx7-q9vq", "GHSA-r936-gwx5-v52f"} {
						assert.True(t, seenIDs[id], "expected GHSA %q in matches", id)
					}
				})
			}
		})

	t.Run("rate-limit error is surfaced", func(t *testing.T) {
		// only the cases that trigger an actual Maven lookup can produce
		// the rate-limit error; "metadata present" returns before the
		// network adapter is touched.
		input := springPackage(pkg.JavaMetadata{
			ArchiveDigests: []pkg.Digest{
				{Algorithm: "sha1", Value: "236e3bfdbdc6c86629237a74f0f11414adb4e211"},
			},
		})
		matcher := newMatcher(mockMavenSearcher{simulateRateLimiting: true})
		dbtest.DBs(t, "spring-webmvc").
			Run(func(t *testing.T, db *dbtest.DB) {
				_, _, err := matcher.matchUpstreamMavenPackages(db, input)
				require.Error(t, err, "expected rate-limit error")
			})
	})
}

// TestMatcherJava_shouldSearchMavenBySha is a pure helper test - it does
// not invoke the matcher and never touches a vulnerability provider, so
// no fixture or mock is involved.
func TestMatcherJava_shouldSearchMavenBySha(t *testing.T) {
	cases := []struct {
		name        string
		metadata    pkg.JavaMetadata
		expectQuery bool
	}{
		{
			name: "do not search maven - metadata present",
			metadata: pkg.JavaMetadata{
				PomArtifactID: "spring-webmvc",
				PomGroupID:    "org.springframework",
				ArchiveDigests: []pkg.Digest{
					{Algorithm: "sha1", Value: "236e3bfdbdc6c86629237a74f0f11414adb4e211"},
				},
			},
			expectQuery: false,
		},
		{
			name: "search maven - missing pom metadata",
			metadata: pkg.JavaMetadata{
				ArchiveDigests: []pkg.Digest{
					{Algorithm: "sha1", Value: "236e3bfdbdc6c86629237a74f0f11414adb4e211"},
				},
			},
			expectQuery: true,
		},
		{
			name: "search maven - missing artifactId only",
			metadata: pkg.JavaMetadata{
				PomGroupID: "org.springframework",
				ArchiveDigests: []pkg.Digest{
					{Algorithm: "sha1", Value: "236e3bfdbdc6c86629237a74f0f11414adb4e211"},
				},
			},
			expectQuery: true,
		},
		{
			name: "do not search maven - missing sha1",
			metadata: pkg.JavaMetadata{
				ArchiveDigests: []pkg.Digest{
					{Algorithm: "sha1", Value: ""},
				},
			},
			expectQuery: false,
		},
	}

	matcher := &Matcher{cfg: MatcherConfig{ExternalSearchConfig: ExternalSearchConfig{SearchMavenUpstream: true}}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := springPackage(c.metadata)
			shouldSearch, digests := matcher.shouldSearchMavenBySha(p)
			assert.Equal(t, c.expectQuery, shouldSearch, "decision to query maven")
			if c.expectQuery {
				assert.NotEmpty(t, digests, "expected digests when search is signalled")
			}
		})
	}
}
