package java

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/stringutil"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

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
	store := newMockProvider()

	// Define test cases
	testCases := []struct {
		testname            string
		testExpectRateLimit bool
		testExpectedError   bool
		packages            []pkg.Package
	}{
		{
			testname:            "do not search maven - metadata present",
			testExpectRateLimit: false,
			testExpectedError:   false,
			packages: []pkg.Package{
				{
					ID:       pkg.ID(uuid.NewString()),
					Name:     "org.springframework.spring-webmvc",
					Version:  "5.1.5.RELEASE",
					Language: syftPkg.Java,
					Type:     syftPkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						PomArtifactID: "spring-webmvc",
						PomGroupID:    "org.springframework",
						ArchiveDigests: []pkg.Digest{
							{
								Algorithm: "sha1",
								Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
							},
						},
					},
				},
			},
		},
		{
			testname:            "search maven - missing metadata",
			testExpectRateLimit: false,
			packages: []pkg.Package{
				{
					ID:       pkg.ID(uuid.NewString()),
					Name:     "org.springframework.spring-webmvc",
					Version:  "5.1.5.RELEASE",
					Language: syftPkg.Java,
					Type:     syftPkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						PomArtifactID: "",
						PomGroupID:    "",
						ArchiveDigests: []pkg.Digest{
							{
								Algorithm: "sha1",
								Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
							},
						},
					},
				},
			},
		},
		{
			testname:            "search maven - missing sha1 error",
			testExpectRateLimit: false,
			testExpectedError:   true,
			packages: []pkg.Package{
				{
					ID:       pkg.ID(uuid.NewString()),
					Name:     "org.springframework.spring-webmvc",
					Version:  "5.1.5.RELEASE",
					Language: syftPkg.Java,
					Type:     syftPkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						PomArtifactID: "",
						PomGroupID:    "",
						ArchiveDigests: []pkg.Digest{
							{
								Algorithm: "sha1",
								Value:     "",
							},
						},
					},
				},
			},
		},
	}

	t.Run("matching from maven search results", func(t *testing.T) {
		for _, p := range testCases {
			// Adding test isolation
			t.Run(p.testname, func(t *testing.T) {
				matcher := newMatcher(mockMavenSearcher{
					pkg: p.packages[0],
				})
				actual, err := matcher.matchUpstreamMavenPackages(store, p.packages[0])

				if p.testExpectedError {
					assert.Error(t, err, "expected an error")
				} else {
					assert.Len(t, actual, 2, "unexpected matches count")

					foundCVEs := stringutil.NewStringSet()
					for _, v := range actual {
						foundCVEs.Add(v.Vulnerability.ID)

						require.NotEmpty(t, v.Details)
						for _, d := range v.Details {
							assert.Equal(t, match.ExactIndirectMatch, d.Type, "indirect match not indicated")
							assert.Equal(t, matcher.Type(), d.Matcher, "failed to capture matcher type")
						}
						assert.Equal(t, p.packages[0].Name, v.Package.Name, "failed to capture original package name")
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
			})
		}
	})

	t.Run("handles maven rate limiting", func(t *testing.T) {
		for _, p := range testCases {
			// Adding test isolation
			t.Run(p.testname, func(t *testing.T) {
				matcher := newMatcher(mockMavenSearcher{simulateRateLimiting: true})

				_, err := matcher.matchUpstreamMavenPackages(store, p.packages[0])

				if p.testExpectRateLimit {
					assert.Errorf(t, err, "should have gotten an error from the rate limiting")
				}
			})
		}
	})
}

func TestMatcherJava_shouldSearchMavenBySha(t *testing.T) {
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

	// Define test cases
	testCases := []struct {
		testname                  string
		expectedShouldSearchMaven bool
		testExpectedError         bool
		packages                  []pkg.Package
	}{
		{
			testname:                  "do not search maven - metadata present",
			expectedShouldSearchMaven: false,
			testExpectedError:         false,
			packages: []pkg.Package{
				{
					ID:       pkg.ID(uuid.NewString()),
					Name:     "org.springframework.spring-webmvc",
					Version:  "5.1.5.RELEASE",
					Language: syftPkg.Java,
					Type:     syftPkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						PomArtifactID: "spring-webmvc",
						PomGroupID:    "org.springframework",
						ArchiveDigests: []pkg.Digest{
							{
								Algorithm: "sha1",
								Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
							},
						},
					},
				},
			},
		},
		{
			testname:                  "search maven - missing metadata",
			expectedShouldSearchMaven: true,
			testExpectedError:         false,
			packages: []pkg.Package{
				{
					ID:       pkg.ID(uuid.NewString()),
					Name:     "org.springframework.spring-webmvc",
					Version:  "5.1.5.RELEASE",
					Language: syftPkg.Java,
					Type:     syftPkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						PomArtifactID: "",
						PomGroupID:    "",
						ArchiveDigests: []pkg.Digest{
							{
								Algorithm: "sha1",
								Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
							},
						},
					},
				},
			},
		},
		{
			testname:                  "search maven - missing artifactId",
			expectedShouldSearchMaven: true,
			testExpectedError:         false,
			packages: []pkg.Package{
				{
					ID:       pkg.ID(uuid.NewString()),
					Name:     "org.springframework.spring-webmvc",
					Version:  "5.1.5.RELEASE",
					Language: syftPkg.Java,
					Type:     syftPkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						PomArtifactID: "",
						PomGroupID:    "org.springframework",
						ArchiveDigests: []pkg.Digest{
							{
								Algorithm: "sha1",
								Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
							},
						},
					},
				},
			},
		},
		{
			testname:                  "search maven - missing sha1 error",
			expectedShouldSearchMaven: true,
			testExpectedError:         true,
			packages: []pkg.Package{
				{
					ID:       pkg.ID(uuid.NewString()),
					Name:     "org.springframework.spring-webmvc",
					Version:  "5.1.5.RELEASE",
					Language: syftPkg.Java,
					Type:     syftPkg.JavaPkg,
					Metadata: pkg.JavaMetadata{
						PomArtifactID: "",
						PomGroupID:    "",
						ArchiveDigests: []pkg.Digest{
							{
								Algorithm: "sha1",
								Value:     "",
							},
						},
					},
				},
			},
		},
	}

	t.Run("matching from Maven search results", func(t *testing.T) {
		for _, p := range testCases {
			// Adding test isolation
			t.Run(p.testname, func(t *testing.T) {
				matcher := newMatcher(mockMavenSearcher{
					pkg: p.packages[0],
				})
				actual, digests, err := matcher.shouldSearchMavenBySha(p.packages[0])

				if p.testExpectedError {
					assert.Error(t, err, "expected an error")
				} else {
					assert.Equal(t, p.expectedShouldSearchMaven, actual, "unexpected decision to search Maven")

					if actual {
						assert.NotEmpty(t, digests, "sha digests should not be empty when search is expected")
					}
				}
			})
		}
	})
}
