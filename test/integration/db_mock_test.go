package integration

import (
	grypeDB "github.com/anchore/grype/grype/db/v5"
)

// integrity check
var _ grypeDB.VulnerabilityStoreReader = &mockStore{}

type mockStore struct {
	normalizedPackageNames map[string]map[string]string
	backend                map[string]map[string][]grypeDB.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, id string) ([]grypeDB.Vulnerability, error) {
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

func (s *mockStore) GetVulnerabilityMatchExclusion(id string) ([]grypeDB.VulnerabilityMatchExclusion, error) {
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
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
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
			"alpine:distro:alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{
					{
						ID:                "CVE-alpine-libvncserver",
						VersionConstraint: "< 0.9.10",
						VersionFormat:     "unknown",
					},
				},
			},
			"gentoo:distro:gentoo:2.8": {
				"app-containers/skopeo": []grypeDB.Vulnerability{
					{
						ID:                "CVE-gentoo-skopeo",
						VersionConstraint: "< 1.6.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:go": {
				"github.com/anchore/coverage": []grypeDB.Vulnerability{
					{
						ID:                "CVE-coverage-main-module-vuln",
						VersionConstraint: "< 1.4.0",
						VersionFormat:     "unknown",
					},
				},
				"github.com/google/uuid": []grypeDB.Vulnerability{
					{
						ID:                "CVE-uuid-vuln",
						VersionConstraint: "< 1.4.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:javascript": {
				"npm": []grypeDB.Vulnerability{
					{
						ID:                "CVE-javascript-validator",
						VersionConstraint: "> 5, < 7.2.1",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:python": {
				"pygments": []grypeDB.Vulnerability{
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
			"github:language:ruby": {
				"bundler": []grypeDB.Vulnerability{
					{
						ID:                "CVE-ruby-bundler",
						VersionConstraint: "> 2.0.0, <= 2.1.4",
						VersionFormat:     "gemfile",
					},
				},
			},
			"github:language:java": {
				"org.anchore:example-java-app-maven": []grypeDB.Vulnerability{
					{
						ID:                "CVE-java-example-java-app",
						VersionConstraint: ">= 0.0.1, < 1.2.0",
						VersionFormat:     "unknown",
					},
				},
			},
			"github:language:dotnet": {
				"awssdk.core": []grypeDB.Vulnerability{
					{
						ID:                "CVE-dotnet-sample",
						VersionConstraint: ">= 3.7.0.0, < 3.7.12.0",
						VersionFormat:     "dotnet",
					},
				},
			},
			"github:language:haskell": {
				"shellcheck": []grypeDB.Vulnerability{
					{
						ID:                "CVE-haskell-sample",
						VersionConstraint: "< 0.9.0",
						VersionFormat:     "haskell",
					},
				},
			},
			"debian:distro:debian:8": {
				"apt-dev": []grypeDB.Vulnerability{
					{
						ID:                "CVE-dpkg-apt",
						VersionConstraint: "<= 1.8.2",
						VersionFormat:     "dpkg",
					},
				},
			},
			"redhat:distro:redhat:8": {
				"dive": []grypeDB.Vulnerability{
					{
						ID:                "CVE-rpmdb-dive",
						VersionConstraint: "<= 1.0.42",
						VersionFormat:     "rpm",
					},
				},
			},
			"msrc:distro:windows:10816": {
				"10816": []grypeDB.Vulnerability{
					{
						ID:                "CVE-2016-3333",
						VersionConstraint: "3200970 || 878787 || base",
						VersionFormat:     "kb",
					},
				},
			},
			"sles:distro:sles:12.5": {
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

func (s *mockStore) SearchForVulnerabilities(namespace, name string) ([]grypeDB.Vulnerability, error) {
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

func (s *mockStore) GetAllVulnerabilities() (*[]grypeDB.Vulnerability, error) {
	return nil, nil
}

func (s *mockStore) GetVulnerabilityMetadata(id string, namespace string) (*grypeDB.VulnerabilityMetadata, error) {
	return nil, nil
}

func (s *mockStore) GetAllVulnerabilityMetadata() (*[]grypeDB.VulnerabilityMetadata, error) {
	return nil, nil
}
