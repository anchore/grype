//+build integration

package integration

import (
	v1 "github.com/anchore/grype-db/pkg/db/v1"
)

// integrity check
var _ v1.VulnerabilityStoreReader = &mockStore{}

type mockStore struct {
	backend map[string]map[string][]v1.Vulnerability
}

func NewMockDbStore() *mockStore {
	return &mockStore{
		backend: map[string]map[string][]v1.Vulnerability{
			"nvd": {
				"libvncserver": []v1.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
			},
			"alpine:3.12": {
				"libvncserver": []v1.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:npm": {
				"validator": []v1.Vulnerability{
					{
						ID:                "CVE-javascript-validator",
						VersionConstraint: "< 3.2.1",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:python": {
				"Pygments": []v1.Vulnerability{
					{
						ID:                "CVE-python-pygments",
						VersionConstraint: "< 2.6.2",
						VersionFormat:     "python",
					},
				},
			},
			"github:gem": {
				"bundler": []v1.Vulnerability{
					{
						ID:                "CVE-ruby-bundler",
						VersionConstraint: "> 2.0.0, <= 2.1.4",
						VersionFormat:     "semver",
					},
				},
			},
			"github:java": {
				"org.anchore:example-java-app-maven": []v1.Vulnerability{
					{
						ID:                "CVE-java-example-java-app",
						VersionConstraint: ">= 0.0.1, < 1.2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"debian:8": {
				"apt-dev": []v1.Vulnerability{
					{
						ID:                "CVE-dpkg-apt",
						VersionConstraint: "<= 1.8.2",
						VersionFormat:     "dpkg",
					},
				},
			},
			"rhel:8": {
				"dive": []v1.Vulnerability{
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

func (s *mockStore) GetVulnerability(namespace, name string) ([]v1.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}
