package java

import (
	"context"
	"testing"
	"time"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func newMockProvider() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			PackageName: "org.springframework.spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.0,<5.1.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-2", Namespace: "github:language:" + syftPkg.Java.String()},
		},
		{
			PackageName: "org.springframework.spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.1,<5.1.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-3", Namespace: "github:language:" + syftPkg.Java.String()},
		},
		// unexpected...
		{
			PackageName: "org.springframework.spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.0,<5.0.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-BAD", Namespace: "github:language:" + syftPkg.Java.String()},
		},
	}...)
}

type mockMavenSearcher struct {
	tb   testing.TB
	pkg  *pkg.Package
	work *time.Duration
}

func newMockSearcher(tb testing.TB) mockMavenSearcher {
	return mockMavenSearcher{
		tb: tb,
	}
}

func (m mockMavenSearcher) WithPackage(p pkg.Package) mockMavenSearcher {
	m.pkg = &p
	return m
}

func (m mockMavenSearcher) WithWorkDuration(duration time.Duration) mockMavenSearcher {
	m.work = &duration
	return m
}

func (m mockMavenSearcher) GetMavenPackageBySha(context.Context, string) (*pkg.Package, error) {
	if m.simulateRateLimiting {
		return nil, errors.New("you been rate limited")
	}
	return &m.pkg, nil
}
