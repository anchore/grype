package java

import (
	"context"
	"testing"
	"time"

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

	p := pkg.Package{
		ID:       pkg.ID(uuid.NewString()),
		Name:     "org.springframework.spring-webmvc",
		Version:  "5.1.5.RELEASE",
		Language: syftPkg.Java,
		Type:     syftPkg.JavaPkg,
		Metadata: pkg.JavaMetadata{
			ArchiveDigests: []pkg.Digest{
				{
					Algorithm: "sha1",
					Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
				},
			},
		},
	}

	t.Run("matching from maven search results", func(t *testing.T) {
		matcher := newMatcher(mockMavenSearcher{
			pkg: p,
		})
		actual, _ := matcher.matchUpstreamMavenPackages(store, p)

		assert.Len(t, actual, 2, "unexpected matches count")

		foundCVEs := stringutil.NewStringSet()
		for _, v := range actual {
			foundCVEs.Add(v.Vulnerability.ID)

			require.NotEmpty(t, v.Details)
			for _, d := range v.Details {
				assert.Equal(t, match.ExactIndirectMatch, d.Type, "indirect match not indicated")
				assert.Equal(t, matcher.Type(), d.Matcher, "failed to capture matcher type")
			}
			assert.Equal(t, p.Name, v.Package.Name, "failed to capture original package name")
		}

		for _, id := range []string{"CVE-2014-fake-2", "CVE-2013-fake-3"} {
			if !foundCVEs.Contains(id) {
				t.Errorf("missing discovered CVE: %s", id)
			}
		}
		if t.Failed() {
			t.Logf("discovered CVES: %+v", foundCVEs)
		}
	})

	t.Run("handles maven rate limiting", func(t *testing.T) {
		matcher := newMatcher(mockMavenSearcher{simulateRateLimiting: true})

		_, err := matcher.matchUpstreamMavenPackages(store, p)

		assert.Errorf(t, err, "should have gotten an error from the rate limiting")
	})
}
func TestMatcherJava_TestMatchUpstreamMavenPackagesTimeout(t *testing.T) {
	p := pkg.Package{
		ID:       pkg.ID(uuid.NewString()),
		Name:     "org.springframework.spring-webmvc",
		Version:  "5.1.5.RELEASE",
		Language: syftPkg.Java,
		Type:     syftPkg.JavaPkg,
		Metadata: pkg.JavaMetadata{
			ArchiveDigests: []pkg.Digest{
				{
					Algorithm: "sha1",
					Value:     "236e3bfdbdc6c86629237a74f0f11414adb4e211",
				},
			},
		},
	}
	matcher := Matcher{
		cfg: MatcherConfig{
			ExternalSearchConfig: ExternalSearchConfig{
				SearchMavenUpstream: true,
			},
			UseCPEs: false,
		},
		MavenSearcher: newMockSearcher(p),
	}
	store := newMockProvider()

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := matcher.matchUpstreamMavenPackages(ctx, store, nil, p)
	// Check if the error is a context deadline exceeded error
	if err == nil {
		t.Errorf("expected an error but got none")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected a context deadline exceeded error but got a different error: %v", err)
	}
}

func TestMatcherJava_TestMatchTimeoutExtraction(t *testing.T) {
	// Create a Matcher with an invalid AbortAfter value
	matcher := Matcher{
		cfg: MatcherConfig{
			ExternalSearchConfig: ExternalSearchConfig{
				SearchMavenUpstream: true,
				AbortAfter:          "invalid_duration", // This cannot be parsed into a duration
			},
			UseCPEs: false,
		},
		MavenSearcher: newMockSearcher(pkg.Package{}),
	}

	// Call Match
	_, err := matcher.Match(nil, nil, pkg.Package{})
	if err == nil {
		t.Error("expected an error but got none")
	} else if !strings.Contains(err.Error(), "failed to parse timeout duration") {
		t.Errorf("expected a 'failed to parse timeout duration' error but got %v", err)
	}
}

func TestMatcherJava_TestMatchWithCorrectAbortAfterVal(t *testing.T) {
	// Create a Matcher with a valid AbortAfter value
	matcher := Matcher{
		cfg: MatcherConfig{
			ExternalSearchConfig: ExternalSearchConfig{
				SearchMavenUpstream: true,
				AbortAfter:          "1ns",
			},
			UseCPEs: false,
		},
		MavenSearcher: newMockSearcher(pkg.Package{}),
	}

	// Call Match
	store := newMockProvider()
	_, err := matcher.Match(store, nil, pkg.Package{})
	if err != nil {
		t.Errorf("expected no error but got %v", err)
	}
}
