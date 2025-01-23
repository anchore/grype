package v6

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// TODO: in a future iteration these should be raised up more explicitly by the vunnel providers
func KnownOperatingSystemSpecifierOverrides() []OperatingSystemSpecifierOverride {
	strRef := func(s string) *string {
		return &s
	}
	return []OperatingSystemSpecifierOverride{
		{Alias: "centos", ReplacementName: strRef("rhel")},
		{Alias: "rocky", ReplacementName: strRef("rhel")},
		{Alias: "rockylinux", ReplacementName: strRef("rhel")}, // non-standard, but common (dockerhub uses "rockylinux")
		{Alias: "alma", ReplacementName: strRef("rhel")},
		{Alias: "almalinux", ReplacementName: strRef("rhel")}, // non-standard, but common (dockerhub uses "almalinux")
		{Alias: "gentoo", ReplacementName: strRef("rhel")},
		{Alias: "alpine", VersionPattern: ".*_alpha.*", ReplacementLabelVersion: strRef("edge"), Rolling: true},
		{Alias: "wolfi", Rolling: true},
		{Alias: "arch", Rolling: true},
		{Alias: "archlinux", ReplacementName: strRef("arch"), Rolling: true}, // non-standard, but common (dockerhub uses "archlinux")
		{Alias: "oracle", ReplacementName: strRef("ol")},                     // non-standard, but common
		{Alias: "oraclelinux", ReplacementName: strRef("ol")},                // non-standard, but common (dockerhub uses "oraclelinux")
		{Alias: "amazon", ReplacementName: strRef("amzn")},                   // non-standard, but common
		{Alias: "amazonlinux", ReplacementName: strRef("amzn")},              // non-standard, but common (dockerhub uses "amazonlinux")
		// TODO: trixie is a placeholder for now, but should be updated to sid when the time comes
		// this needs to be automated, but isn't clear how to do so since you'll see things like this:
		//
		// ❯ docker run --rm debian:sid cat /etc/os-release | grep VERSION_CODENAME
		//   VERSION_CODENAME=trixie
		// ❯ docker run --rm debian:testing cat /etc/os-release | grep VERSION_CODENAME
		//   VERSION_CODENAME=trixie
		//
		// ❯ curl -s http://deb.debian.org/debian/dists/testing/Release | grep '^Codename:'
		//   Codename: trixie
		// ❯ curl -s http://deb.debian.org/debian/dists/sid/Release | grep '^Codename:'
		//   Codename: sid
		//
		// depending where the team is during the development cycle you will see different behavior, making automating
		// this a little challenging.
		{Alias: "debian", Codename: "trixie", Rolling: true}, // is currently sid, which is considered rolling
	}
}

func KnownPackageSpecifierOverrides() []PackageSpecifierOverride {
	// when matching packages, grype will always attempt to do so based off of the package type which means
	// that any request must be in terms of the package type (relative to syft).

	// remap package URL types to syft package types
	var ret []PackageSpecifierOverride
	for _, t := range pkg.AllPkgs {
		purlType := t.PackageURLType()
		if purlType == "" || purlType == string(t) || strings.HasPrefix(purlType, "generic") {
			continue
		}

		ret = append(ret, PackageSpecifierOverride{
			Ecosystem:            purlType,
			ReplacementEcosystem: ptr(string(t)),
		})
	}
	return ret
}

func ptr[T any](v T) *T {
	return &v
}
