package integration

import (
	grypeDB "github.com/anchore/grype/grype/db/v3"
)

// integrity check
var _ grypeDB.VulnerabilityStoreReader = &mockStore{}

type mockStore struct {
	backend map[string]map[string][]grypeDB.Vulnerability
}

func newMockDbStore() *mockStore {
	return &mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			grypeDB.NVDNamespace: {
				"libvncserver": []grypeDB.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
				"my-package": []grypeDB.Vulnerability{
					{
						ID:                "CVE-bogus-my-package-1",
						VersionConstraint: "< 2.0",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:bogus:my-package:*:*:*:*:*:*:something:*"},
					},
					{
						ID:                "CVE-bogus-my-package-2-never-match",
						VersionConstraint: "< 2.0",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:something-wrong:my-package:*:*:*:*:*:*:something:*"},
					},
				},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:npm": {
				"npm": []grypeDB.Vulnerability{
					{
						ID:                "CVE-javascript-validator",
						VersionConstraint: "> 5, < 7.2.1",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:python": {
				"Pygments": []grypeDB.Vulnerability{
					{
						ID:                "CVE-python-pygments",
						VersionConstraint: "< 2.6.2",
						VersionFormat:     "python",
					},
				},
				"my-package": []grypeDB.Vulnerability{
					{
						ID:                "CVE-bogus-my-package-2-python",
						VersionConstraint: "< 2.0",
						VersionFormat:     "python",
					},
				},
			},
			"github:gem": {
				"bundler": []grypeDB.Vulnerability{
					{
						ID:                "CVE-ruby-bundler",
						VersionConstraint: "> 2.0.0, <= 2.1.4",
						VersionFormat:     "semver",
					},
				},
			},
			"github:java": {
				"org.anchore:example-java-app-maven": []grypeDB.Vulnerability{
					{
						ID:                "CVE-java-example-java-app",
						VersionConstraint: ">= 0.0.1, < 1.2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:nuget": {
				"AWSSDK.Core": []grypeDB.Vulnerability{
					{
						ID:                "CVE-dotnet-sample",
						VersionConstraint: ">= 3.7.0.0, < 3.7.12.0",
						VersionFormat:     "dotnet",
					},
				},
			},
			"debian:8": {
				"apt-dev": []grypeDB.Vulnerability{
					{
						ID:                "CVE-dpkg-apt",
						VersionConstraint: "<= 1.8.2",
						VersionFormat:     "dpkg",
					},
				},
			},
			"rhel:8": {
				"dive": []grypeDB.Vulnerability{
					{
						ID:                "CVE-rpmdb-dive",
						VersionConstraint: "<= 1.0.42",
						VersionFormat:     "rpm",
					},
				},
			},
			"msrc:10816": {
				"10816": []grypeDB.Vulnerability{
					{
						ID:                "CVE-2016-3333",
						VersionConstraint: "3200970 || 878787 || base",
						VersionFormat:     "kb",
					},
				},
			},
			"sles:12.5": {
				"dive": []grypeDB.Vulnerability{
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

func (s *mockStore) GetVulnerability(namespace, name string) ([]grypeDB.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	entries, ok := namespaceMap[name]
	if !ok {
		return entries, nil
	}
	for i := range entries {
		entries[i].Namespace = namespace
	}
	return entries, nil
}

func (s *mockStore) GetAllSerializedVulnerabilities() (interface{}, error) {
	return nil, nil
}
