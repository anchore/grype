package integration

import (
	griffonDB "github.com/nextlinux/griffon/griffon/db/v5"
)

// integrity check
var _ griffonDB.VulnerabilityStoreReader = &mockStore{}

type mockStore struct {
	normalizedPackageNames map[string]map[string]string
	backend                map[string]map[string][]griffonDB.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, id string) ([]griffonDB.Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

func (s *mockStore) GetVulnerabilityNamespaces() ([]string, error) {
	var results []string
	for k := range s.backend {
		results = append(results, k)
	}

	return results, nil
}

func (s *mockStore) GetVulnerabilityMatchExclusion(id string) ([]griffonDB.VulnerabilityMatchExclusion, error) {
	return nil, nil
}

func newMockDbStore() *mockStore {
	return &mockStore{
		normalizedPackageNames: map[string]map[string]string{
			"github:language:python": {
				"Pygments":   "pygments",
				"my-package": "my-package",
			},
			"github:language:dotnet": {
				"AWSSDK.Core": "awssdk.core",
			},
		},
		backend: map[string]map[string][]griffonDB.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []griffonDB.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
				"my-package": []griffonDB.Vulnerability{
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
			"alpine:distro:alpine:3.12": {
				"libvncserver": []griffonDB.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
					},
				},
			},
			"gentoo:distro:gentoo:2.8": {
				"app-containers/skopeo": []griffonDB.Vulnerability{
					{
						ID:                "CVE-gentoo-skopeo",
						VersionConstraint: "< 1.6.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:go": {
				"github.com/anchore/coverage": []griffonDB.Vulnerability{
					{
						ID:                "CVE-coverage-main-module-vuln",
						VersionConstraint: "< 1.4.0",
						VersionFormat:     "unknown",
					},
				},
				"github.com/google/uuid": []griffonDB.Vulnerability{
					{
						ID:                "CVE-uuid-vuln",
						VersionConstraint: "< 1.4.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:javascript": {
				"npm": []griffonDB.Vulnerability{
					{
						ID:                "CVE-javascript-validator",
						VersionConstraint: "> 5, < 7.2.1",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:python": {
				"pygments": []griffonDB.Vulnerability{
					{
						ID:                "CVE-python-pygments",
						VersionConstraint: "< 2.6.2",
						VersionFormat:     "python",
					},
				},
				"my-package": []griffonDB.Vulnerability{
					{
						ID:                "CVE-bogus-my-package-2-python",
						VersionConstraint: "< 2.0",
						VersionFormat:     "python",
					},
				},
			},
			"github:language:ruby": {
				"bundler": []griffonDB.Vulnerability{
					{
						ID:                "CVE-ruby-bundler",
						VersionConstraint: "> 2.0.0, <= 2.1.4",
						VersionFormat:     "gemfile",
					},
				},
			},
			"github:language:java": {
				"org.anchore:example-java-app-maven": []griffonDB.Vulnerability{
					{
						ID:                "CVE-java-example-java-app",
						VersionConstraint: ">= 0.0.1, < 1.2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:dotnet": {
				"awssdk.core": []griffonDB.Vulnerability{
					{
						ID:                "CVE-dotnet-sample",
						VersionConstraint: ">= 3.7.0.0, < 3.7.12.0",
						VersionFormat:     "dotnet",
					},
				},
			},
			"github:language:haskell": {
				"shellcheck": []griffonDB.Vulnerability{
					{
						ID:                "CVE-haskell-sample",
						VersionConstraint: "< 0.9.0",
						VersionFormat:     "haskell",
					},
				},
			},
			"debian:distro:debian:8": {
				"apt-dev": []griffonDB.Vulnerability{
					{
						ID:                "CVE-dpkg-apt",
						VersionConstraint: "<= 1.8.2",
						VersionFormat:     "dpkg",
					},
				},
			},
			"redhat:distro:redhat:8": {
				"dive": []griffonDB.Vulnerability{
					{
						ID:                "CVE-rpmdb-dive",
						VersionConstraint: "<= 1.0.42",
						VersionFormat:     "rpm",
					},
				},
			},
			"msrc:distro:windows:10816": {
				"10816": []griffonDB.Vulnerability{
					{
						ID:                "CVE-2016-3333",
						VersionConstraint: "3200970 || 878787 || base",
						VersionFormat:     "kb",
					},
				},
			},
			"sles:distro:sles:12.5": {
				"dive": []griffonDB.Vulnerability{
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

func (s *mockStore) SearchForVulnerabilities(namespace, name string) ([]griffonDB.Vulnerability, error) {
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

func (s *mockStore) GetAllVulnerabilities() (*[]griffonDB.Vulnerability, error) {
	return nil, nil
}

func (s *mockStore) GetVulnerabilityMetadata(id string, namespace string) (*griffonDB.VulnerabilityMetadata, error) {
	return nil, nil
}

func (s *mockStore) GetAllVulnerabilityMetadata() (*[]griffonDB.VulnerabilityMetadata, error) {
	return nil, nil
}
