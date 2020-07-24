package integration

import (
	"github.com/anchore/siren-db/pkg/db"
)

// integrity check
var _ db.VulnerabilityStoreReader = &mockStore{}

type mockStore struct {
	backend map[string]map[string][]db.Vulnerability
}

func NewMockDbStore() *mockStore {
	return &mockStore{
		backend: map[string]map[string][]db.Vulnerability{
			"github:npm": {
				"validator": []db.Vulnerability{
					{
						ID:                "CVE-javascript-validator",
						VersionConstraint: "< 3.2.1",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:python": {
				"Pygments": []db.Vulnerability{
					{
						ID:                "CVE-python-pygments",
						VersionConstraint: "< 2.6.2",
						VersionFormat:     "semver",
					},
				},
			},
			"github:gem": {
				"rails": []db.Vulnerability{
					{
						ID:                "CVE-ruby-activerecord",
						VersionConstraint: "> 4.0.0, <= 4.1.1",
						VersionFormat:     "semver",
					},
				},
			},
			"github:java": {
				"org.anchore:example-java-app-maven": []db.Vulnerability{
					{
						ID:                "CVE-java-example-java-app",
						VersionConstraint: ">= 0.0.1, < 1.2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"debian:8": {
				"apt-dev": []db.Vulnerability{
					{
						ID:                "CVE-dpkg-apt",
						VersionConstraint: "<= 1.8.2",
						VersionFormat:     "dpkg",
					},
				},
			},
			"rhel:8": {
				"dive": []db.Vulnerability{
					{
						ID:                "CVE-rpmdb-dive",
						VersionConstraint: "<= 1.0.42",
						VersionFormat:     "rpm",
					},
				},
			},
		},
	}
}

func (s *mockStore) GetVulnerability(namespace, name string) ([]db.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}
