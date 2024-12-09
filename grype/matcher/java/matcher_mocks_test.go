package java

import (
	"context"
	"testing"
	"time"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockProvider struct {
	data map[syftPkg.Language]map[string][]vulnerability.Vulnerability
}

func (mp *mockProvider) Get(id, namespace string) ([]vulnerability.Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

func (mp *mockProvider) populateData() {
	mp.data[syftPkg.Java] = map[string][]vulnerability.Vulnerability{
		"org.springframework.spring-webmvc": {
			{
				Constraint: version.MustGetConstraint(">=5.0.0,<5.1.7", version.UnknownFormat),
				ID:         "CVE-2014-fake-2",
			},
			{
				Constraint: version.MustGetConstraint(">=5.0.1,<5.1.7", version.UnknownFormat),
				ID:         "CVE-2013-fake-3",
			},
			// unexpected...
			{
				Constraint: version.MustGetConstraint(">=5.0.0,<5.0.7", version.UnknownFormat),
				ID:         "CVE-2013-fake-BAD",
			},
		},
	}
}

func newMockProvider() *mockProvider {
	mp := mockProvider{
		data: make(map[syftPkg.Language]map[string][]vulnerability.Vulnerability),
	}

	mp.populateData()

	return &mp
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

func (m mockMavenSearcher) GetMavenPackageBySha(ctx context.Context, sha1 string) (*pkg.Package, error) {
	deadline, ok := ctx.Deadline()

	m.tb.Log("GetMavenPackageBySha called with deadline:", deadline, "deadline set:", ok)

	if m.work != nil {
		select {
		case <-time.After(*m.work):
			return m.pkg, nil
		case <-ctx.Done():
			// If the context is done before the sleep is over, return a context.DeadlineExceeded error
			return m.pkg, ctx.Err()
		}
	} else {
		return m.pkg, ctx.Err()
	}
}

func (mp *mockProvider) GetByCPE(p cpe.CPE) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (mp *mockProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (mp *mockProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return mp.data[l][p.Name], nil
}
