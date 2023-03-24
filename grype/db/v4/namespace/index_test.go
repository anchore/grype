package namespace

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/db/v4/namespace/cpe"
	"github.com/anchore/grype/grype/db/v4/namespace/distro"
	"github.com/anchore/grype/grype/db/v4/namespace/language"
	osDistro "github.com/anchore/grype/grype/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestFromStringSlice(t *testing.T) {
	tests := []struct {
		namespaces  []string
		byLanguage  map[syftPkg.Language][]*language.Namespace
		byDistroKey map[string][]*distro.Namespace
		cpe         []*cpe.Namespace
	}{
		{
			namespaces: []string{
				"github:language:python",
				"github:language:python:conda",
				"debian:distro:debian:8",
				"alpine:distro:alpine:3.15",
				"alpine:distro:alpine:3.16",
				"msrc:distro:windows:12345",
				"nvd:cpe",
				"github:language:ruby",
				"abc.xyz:language:ruby",
				"1234.4567:language:unknown",
				"---:cpe",
				"another-provider:distro:alpine:3.15",
				"another-provider:distro:alpine:3.16",
			},
			byLanguage: map[syftPkg.Language][]*language.Namespace{
				syftPkg.Python: {
					language.NewNamespace("github", syftPkg.Python, ""),
					language.NewNamespace("github", syftPkg.Python, syftPkg.Type("conda")),
				},
				syftPkg.Ruby: {
					language.NewNamespace("github", syftPkg.Ruby, ""),
					language.NewNamespace("abc.xyz", syftPkg.Ruby, ""),
				},
				syftPkg.Language("unknown"): {
					language.NewNamespace("1234.4567", syftPkg.Language("unknown"), ""),
				},
			},
			byDistroKey: map[string][]*distro.Namespace{
				"debian:8": {
					distro.NewNamespace("debian", osDistro.Debian, "8"),
				},
				"alpine:3.15": {
					distro.NewNamespace("alpine", osDistro.Alpine, "3.15"),
					distro.NewNamespace("another-provider", osDistro.Alpine, "3.15"),
				},
				"alpine:3.16": {
					distro.NewNamespace("alpine", osDistro.Alpine, "3.16"),
					distro.NewNamespace("another-provider", osDistro.Alpine, "3.16"),
				},
				"windows:12345": {
					distro.NewNamespace("msrc", osDistro.Windows, "12345"),
				},
			},
			cpe: []*cpe.Namespace{
				cpe.NewNamespace("---"),
				cpe.NewNamespace("nvd"),
			},
		},
	}

	for _, test := range tests {
		result, _ := FromStrings(test.namespaces)
		assert.Len(t, result.all, len(test.namespaces))

		for l, elems := range result.byLanguage {
			assert.Contains(t, test.byLanguage, l)
			assert.ElementsMatch(t, elems, test.byLanguage[l])
		}

		for d, elems := range result.byDistroKey {
			assert.Contains(t, test.byDistroKey, d)
			assert.ElementsMatch(t, elems, test.byDistroKey[d])
		}

		assert.ElementsMatch(t, result.cpe, test.cpe)
	}
}

func TestIndex_CPENamespaces(t *testing.T) {
	tests := []struct {
		namespaces []string
		cpe        []*cpe.Namespace
	}{
		{
			namespaces: []string{"nvd:cpe", "another-source:cpe", "x:distro:y:10"},
			cpe: []*cpe.Namespace{
				cpe.NewNamespace("nvd"),
				cpe.NewNamespace("another-source"),
			},
		},
	}

	for _, test := range tests {
		result, _ := FromStrings(test.namespaces)
		assert.Len(t, result.all, len(test.namespaces))
		assert.ElementsMatch(t, result.CPENamespaces(), test.cpe)
	}
}

func newDistro(t *testing.T, dt osDistro.Type, v string, idLikes []string) *osDistro.Distro {
	distro, err := osDistro.New(dt, v, idLikes...)
	assert.NoError(t, err)
	return distro
}

func TestIndex_NamespacesForDistro(t *testing.T) {
	namespaceIndex, err := FromStrings([]string{
		"alpine:distro:alpine:3.15",
		"alpine:distro:alpine:3.16",
		"debian:distro:debian:8",
		"amazon:distro:amazonlinux:2",
		"amazon:distro:amazonlinux:2022",
		"abc.xyz:distro:unknown:123.456",
		"redhat:distro:redhat:8",
		"redhat:distro:redhat:9",
		"other-provider:distro:debian:8",
		"other-provider:distro:redhat:9",
		"suse:distro:sles:12.5",
		"msrc:distro:windows:471816",
		"ubuntu:distro:ubuntu:18.04",
		"oracle:distro:oraclelinux:8",
		"wolfi:distro:wolfi:rolling",
		"chainguard:distro:chainguard:rolling",
		"archlinux:distro:archlinux:rolling",
	})

	assert.NoError(t, err)

	tests := []struct {
		distro     *osDistro.Distro
		namespaces []*distro.Namespace
	}{
		{
			distro: newDistro(t, osDistro.Alpine, "3.15.4", []string{"alpine"}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "3.15"),
			},
		},
		{
			distro: newDistro(t, osDistro.Alpine, "3.16", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "3.16"),
			},
		},
		{
			distro:     newDistro(t, osDistro.Alpine, "3.16.4.5", []string{}),
			namespaces: nil,
		},
		{
			distro: newDistro(t, osDistro.Debian, "8.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("debian", osDistro.Debian, "8"),
				distro.NewNamespace("other-provider", osDistro.Debian, "8"),
			},
		},
		{
			distro: newDistro(t, osDistro.RedHat, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			distro: newDistro(t, osDistro.CentOS, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			distro: newDistro(t, osDistro.AlmaLinux, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			distro: newDistro(t, osDistro.RockyLinux, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			distro: newDistro(t, osDistro.SLES, "12.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("suse", osDistro.SLES, "12.5"),
			},
		},
		{
			distro: newDistro(t, osDistro.Windows, "471816", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("msrc", osDistro.Windows, "471816"),
			},
		},
		{
			distro: newDistro(t, osDistro.Ubuntu, "18.04", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("ubuntu", osDistro.Ubuntu, "18.04"),
			},
		},
		{
			distro:     newDistro(t, osDistro.Fedora, "31.4", []string{}),
			namespaces: nil,
		},
		{
			distro: newDistro(t, osDistro.AmazonLinux, "2", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("amazon", osDistro.AmazonLinux, "2"),
			},
		},
		{
			distro: newDistro(t, osDistro.AmazonLinux, "2022", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("amazon", osDistro.AmazonLinux, "2022"),
			},
		},
		{
			distro:     newDistro(t, osDistro.Mariner, "20.1", []string{}),
			namespaces: nil,
		},
		{
			distro: newDistro(t, osDistro.OracleLinux, "8", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("oracle", osDistro.OracleLinux, "8"),
			},
		},
		{
			distro: newDistro(t, osDistro.ArchLinux, "", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("archlinux", osDistro.ArchLinux, "rolling"),
			},
		},
		{
			// Gentoo is a rolling distro; however, because we currently have no namespaces populated for it in the
			// index fixture, we expect to get nil
			distro:     newDistro(t, osDistro.Gentoo, "", []string{}),
			namespaces: nil,
		},
		{
			distro:     newDistro(t, osDistro.OpenSuseLeap, "100", []string{}),
			namespaces: nil,
		},
		{
			distro:     newDistro(t, osDistro.Photon, "20.1", []string{}),
			namespaces: nil,
		},
		{
			distro:     newDistro(t, osDistro.Busybox, "20.1", []string{}),
			namespaces: nil,
		},
		{
			distro: newDistro(t, osDistro.Wolfi, "20221011", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("wolfi", osDistro.Wolfi, "rolling"),
			},
		},
		{
			distro: newDistro(t, osDistro.Chainguard, "20230214", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("chainguard", osDistro.Chainguard, "rolling"),
			},
		},
	}

	for _, test := range tests {
		result := namespaceIndex.NamespacesForDistro(test.distro)
		assert.ElementsMatch(t, result, test.namespaces)
	}
}
