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

// TestMatcherJava_ChainguardLibrariesSuppressesUpstreamGhsa exercises
// the chainguard-libraries (annotated-openvex) suppression flow for
// maven packages. CGA-3mj7-wxw9-qjx2 declares
// pkg:maven/org.springframework.security/spring-security-web@5.8.16-0.cgr.1
// status=fixed for the upstream GHSA-mf92-479x-3373 (CVE-2026-22732).
// The v6 build pipeline must record the unaffected handle under the
// same "groupId:artifactId" name that the github advisory transformer
// uses for Java packages, otherwise the matcher's name-keyed search
// would silently miss the VEX statement and the upstream GHSA would
// still fire on the rebuilt artifact. This test pins both halves of
// that contract:
//
//   - vanilla spring-security-web 5.8.16 still matches the upstream
//     GHSA (no chainguard rebuild involved).
//   - the chainguard rebuild 5.8.16-0.cgr.1 emits no matches and
//     surfaces three UnaffectedPackageEntry IgnoreRules - one per
//     alias on the CGA (CGA-3mj7-wxw9-qjx2, CVE-2026-22732,
//     GHSA-mf92-479x-3373) - all keyed to the scanned package
//     coordinates so consumers can carry the suppression forward.
//   - past the upstream fix (7.0.4) the package is clean.
//
// The sample SBOMs in /Users/williammurphy/work/tools/sample-material
// drive the same scenario with a Spring Boot 3 / spring-security 6.4.x
// app: the cgr-rebuilt jar (6.4.13-0.cgr.1) only suppresses upstream
// findings if the chainguard-libraries provider has published a CGA
// for that exact rebuild, which it has not yet at the time of writing
// for the 6.4 line. The 5.8.16-0.cgr.1 pairing here is used because
// it is the cleanest currently-published example.
func TestMatcherJava_ChainguardLibrariesSuppressesUpstreamGhsa(t *testing.T) {
	const (
		chainguardCGA  = "CGA-3mj7-wxw9-qjx2"
		upstreamCVE    = "CVE-2026-22732"
		upstreamGHSA   = "GHSA-mf92-479x-3373"
		unaffectedRule = "UnaffectedPackageEntry"
	)

	mk := func(version string) pkg.Package {
		return dbtest.NewPackage("org.springframework.security.spring-security-web", version, syftPkg.JavaPkg).
			WithLanguage(syftPkg.Java).
			WithMetadata(pkg.JavaMetadata{
				PomArtifactID: "spring-security-web",
				PomGroupID:    "org.springframework.security",
			}).
			Build()
	}

	dbtest.DBs(t, "spring-security-and-vex").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewJavaMatcher(MatcherConfig{})

			t.Run("vanilla 5.8.16 still matches the upstream GHSA", func(t *testing.T) {
				db.Match(t, matcher, mk("5.8.16")).
					SelectMatch(upstreamGHSA).
					SelectDetailByType(match.ExactDirectMatch).
					AsEcosystemSearch()
			})

			t.Run("chainguard rebuild 5.8.16-0.cgr.1 drops the GHSA and emits VEX-style ignore rules", func(t *testing.T) {
				const cgrVersion = "5.8.16-0.cgr.1"
				findings := db.Match(t, matcher, mk(cgrVersion))
				ignores := findings.Ignores()
				ignores.SelectIgnoreRule(unaffectedRule, chainguardCGA).
					ForPackage("org.springframework.security.spring-security-web", cgrVersion).
					IncludesAliases()
				ignores.SelectIgnoreRule(unaffectedRule, upstreamCVE).
					ForPackage("org.springframework.security.spring-security-web", cgrVersion).
					IncludesAliases()
				ignores.SelectIgnoreRule(unaffectedRule, upstreamGHSA).
					ForPackage("org.springframework.security.spring-security-web", cgrVersion).
					IncludesAliases()
			})

			t.Run("spring-security-web past upstream fix is clean - no match, no ignore", func(t *testing.T) {
				db.Match(t, matcher, mk("7.0.4")).IsEmpty()
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
