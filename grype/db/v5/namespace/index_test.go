package namespace

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/db/v5/namespace/cpe"
	"github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
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
				"github:language:rust",
				"something:language:rust",
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
				syftPkg.Rust: {
					language.NewNamespace("github", syftPkg.Rust, ""),
					language.NewNamespace("something", syftPkg.Rust, ""),
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
	d, err := osDistro.New(dt, v, idLikes...)
	assert.NoError(t, err)
	return d
}

func TestIndex_NamespacesForDistro(t *testing.T) {
	namespaceIndex, err := FromStrings([]string{
		"alpine:distro:alpine:2.17",
		"alpine:distro:alpine:3.15",
		"alpine:distro:alpine:3.16",
		"alpine:distro:alpine:4.13",
		"alpine:distro:alpine:edge",
		"debian:distro:debian:8",
		"debian:distro:debian:unstable",
		"amazon:distro:amazonlinux:2",
		"amazon:distro:amazonlinux:2022",
		"abc.xyz:distro:unknown:123.456",
		"redhat:distro:redhat:8",
		"redhat:distro:redhat:9",
		"other-provider:distro:debian:8",
		"other-provider:distro:redhat:9",
		"suse:distro:sles:12.5",
		"mariner:distro:mariner:2.0",
		"mariner:distro:azurelinux:3.0",
		"msrc:distro:windows:471816",
		"ubuntu:distro:ubuntu:18.04",
		"ubuntu:distro:ubuntu:18.10",
		"ubuntu:distro:ubuntu:20.04",
		"ubuntu:distro:ubuntu:20.10",
		"oracle:distro:oraclelinux:8",
		"wolfi:distro:wolfi:rolling",
		"chainguard:distro:chainguard:rolling",
		"archlinux:distro:archlinux:rolling",
	})

	assert.NoError(t, err)

	tests := []struct {
		name       string
		distro     *osDistro.Distro
		namespaces []*distro.Namespace
	}{
		{
			name:   "alpine patch version matches minor version namespace",
			distro: newDistro(t, osDistro.Alpine, "3.15.4", []string{"alpine"}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "3.15"),
			},
		},
		{
			name:   "alpine missing patch version matches with minor version",
			distro: newDistro(t, osDistro.Alpine, "3.16", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "3.16"),
			},
		},
		{
			name:   "alpine missing minor version uses latest minor version",
			distro: newDistro(t, osDistro.Alpine, "3", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "3.16"),
			},
		},
		{
			name:   "ubuntu missing minor version uses latest minor version",
			distro: newDistro(t, osDistro.Ubuntu, "18", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("ubuntu", osDistro.Ubuntu, "18.10"),
			},
		},
		{
			name:   "alpine rc version with no patch should match edge",
			distro: newDistro(t, osDistro.Alpine, "3.16.4-r4", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "edge"),
			},
		},

		{
			name:   "alpine edge version matches edge namespace",
			distro: &osDistro.Distro{Type: osDistro.Alpine, Version: nil, RawVersion: "3.17.1_alpha20221002", IDLike: []string{"alpine"}},
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "edge"),
			},
		},
		{
			name:   "alpine raw version matches edge with - character",
			distro: &osDistro.Distro{Type: osDistro.Alpine, Version: nil, RawVersion: "3.17.1-alpha20221002", IDLike: []string{"alpine"}},
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "edge"),
			},
		},
		{
			name:   "alpine raw version matches edge with - character no sha",
			distro: newDistro(t, osDistro.Alpine, "3.17.1-alpha", []string{"alpine"}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "edge"),
			},
		},
		{
			name: "alpine raw version matches edge with _ character no sha",
			// we don't create a newDistro from this since parsing the version fails
			distro: &osDistro.Distro{Type: osDistro.Alpine, Version: nil, RawVersion: "3.17.1_alpha", IDLike: []string{"alpine"}},
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "edge"),
			},
		},
		{
			name:   "alpine malformed version matches with closest",
			distro: newDistro(t, osDistro.Alpine, "3.16.4.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("alpine", osDistro.Alpine, "3.16"),
			},
		},
		{
			name:   "Debian minor version matches debian and other-provider namespaces",
			distro: newDistro(t, osDistro.Debian, "8.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("debian", osDistro.Debian, "8"),
				distro.NewNamespace("other-provider", osDistro.Debian, "8"),
			},
		},
		{
			name:   "Redhat minor version matches redhat and other-provider namespaces",
			distro: newDistro(t, osDistro.RedHat, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			name:   "Centos minor version matches redhat and other-provider namespaces",
			distro: newDistro(t, osDistro.CentOS, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			name:   "Alma Linux minor version matches redhat and other-provider namespaces",
			distro: newDistro(t, osDistro.AlmaLinux, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			name:   "Rocky Linux minor version matches redhat and other-provider namespaces",
			distro: newDistro(t, osDistro.RockyLinux, "9.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("redhat", osDistro.RedHat, "9"),
				distro.NewNamespace("other-provider", osDistro.RedHat, "9"),
			},
		},
		{
			name:   "SLES minor version matches suse namespace",
			distro: newDistro(t, osDistro.SLES, "12.5", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("suse", osDistro.SLES, "12.5"),
			},
		},
		{
			name:   "Windows version object matches msrc namespace with exact version",
			distro: newDistro(t, osDistro.Windows, "471816", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("msrc", osDistro.Windows, "471816"),
			},
		},
		{
			name:   "Ubuntu minor semvar matches ubuntu namespace with exact version",
			distro: newDistro(t, osDistro.Ubuntu, "18.04", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("ubuntu", osDistro.Ubuntu, "18.04"),
			},
		},
		{
			name:       "Fedora minor semvar will not match a namespace",
			distro:     newDistro(t, osDistro.Fedora, "31.4", []string{}),
			namespaces: nil,
		},
		{
			name:   "Amazon Linux Major semvar matches amazon namespace with exact version",
			distro: newDistro(t, osDistro.AmazonLinux, "2", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("amazon", osDistro.AmazonLinux, "2"),
			},
		},
		{
			name:   "Amazon Linux year version matches amazon namespace with exact uear",
			distro: newDistro(t, osDistro.AmazonLinux, "2022", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("amazon", osDistro.AmazonLinux, "2022"),
			},
		},
		{
			name:       "Mariner minor semvar matches no namespace",
			distro:     newDistro(t, osDistro.Mariner, "20.1", []string{}),
			namespaces: nil,
		},
		{
			name:   "Mariner 2.0 matches mariner namespace",
			distro: newDistro(t, osDistro.Mariner, "2.0", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("mariner", "mariner", "2.0"),
			},
		},
		{
			name:   "azurelinux 3 is matched by mariner 3 namespace",
			distro: newDistro(t, osDistro.Azure, "3.0", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("mariner", osDistro.Azure, "3.0"),
			},
		},
		{
			name:   "Oracle Linux Major semvar matches oracle namespace with exact version",
			distro: newDistro(t, osDistro.OracleLinux, "8", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("oracle", osDistro.OracleLinux, "8"),
			},
		},
		{

			name:   "Arch Linux matches archlinux rolling namespace",
			distro: newDistro(t, osDistro.ArchLinux, "", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("archlinux", osDistro.ArchLinux, "rolling"),
			},
		},
		{

			name:   "Wolfi matches wolfi rolling namespace",
			distro: newDistro(t, osDistro.Wolfi, "20221011", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("wolfi", osDistro.Wolfi, "rolling"),
			},
		},
		{

			name:   "Chainguard matches chainguard rolling namespace",
			distro: newDistro(t, osDistro.Chainguard, "20230214", []string{}),
			namespaces: []*distro.Namespace{
				distro.NewNamespace("chainguard", osDistro.Chainguard, "rolling"),
			},
		},
		{

			name:       "Gentoo doesn't match any namespace since the gentoo rolling namespace doesn't exist in index",
			distro:     newDistro(t, osDistro.Gentoo, "", []string{}),
			namespaces: nil,
		},
		{
			name:       "Open Suse Leap semvar matches no namespace",
			distro:     newDistro(t, osDistro.OpenSuseLeap, "100", []string{}),
			namespaces: nil,
		},
		{
			name:       "Photon minor semvar no namespace",
			distro:     newDistro(t, osDistro.Photon, "20.1", []string{}),
			namespaces: nil,
		},
		{
			name:       "Busybox minor semvar matches no namespace",
			distro:     newDistro(t, osDistro.Busybox, "20.1", []string{}),
			namespaces: nil,
		},
		{
			name: "debian unstable",
			distro: &osDistro.Distro{
				Type:       osDistro.Debian,
				RawVersion: "unstable",
				Version:    nil,
			},
			namespaces: []*distro.Namespace{
				distro.NewNamespace("debian", osDistro.Debian, "unstable"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespaces := namespaceIndex.NamespacesForDistro(test.distro)
			assert.ElementsMatch(t, test.namespaces, namespaces)
		})
	}
}
