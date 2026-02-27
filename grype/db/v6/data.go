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
		// redhat clones or otherwise shared vulnerability data
		{Alias: "centos", ReplacementName: strRef("rhel")},
		{Alias: "rocky", ReplacementName: strRef("rhel")},
		{Alias: "rockylinux", ReplacementName: strRef("rhel")}, // non-standard, but common (dockerhub uses "rockylinux")
		{Alias: "alma", ReplacementName: strRef("rhel")},
		{Alias: "almalinux", ReplacementName: strRef("rhel")}, // non-standard, but common (dockerhub uses "almalinux")
		{Alias: "scientific", ReplacementName: strRef("rhel")},
		{Alias: "sl", ReplacementName: strRef("rhel")}, // non-standard, but common (dockerhub uses "sl")
		{Alias: "gentoo", ReplacementName: strRef("rhel")},

		// Alternaitve distros that should match against the debian vulnerability data
		{Alias: "raspbian", ReplacementName: strRef("debian")},

		// to remain backwards compatible, we need to keep old clients from ignoring EUS data.
		// we do this by diverting any requests for a specific major.minor version of rhel to only
		// use the major version. But, this only applies to clients before v6.0.3 DB schema version.
		// Why 6.0.3? This is when OS channel was introduced, which grype-db will leverage, and add additional
		// rhel rows to the DB, all which have major.minor versions. This means that any old client (which wont
		// see the new channel column) will assume during OS resolution that there is major.minor vuln data
		// that should be used (which is incorrect).
		{Alias: "rhel", VersionPattern: `^\d+\.\d+`, ReplacementMinorVersion: strRef(""), ApplicableClientDBSchemas: "< 6.0.3"},
		// we pass in the distro.Type into the search specifier, not a raw release-id
		{Alias: "redhat", VersionPattern: `^\d+\.\d+`, ReplacementMinorVersion: strRef(""), ReplacementName: strRef("rhel"), ApplicableClientDBSchemas: "< 6.0.3"},

		// alpine family
		{Alias: "alpine", VersionPattern: `.*_alpha.*`, ReplacementLabelVersion: strRef("edge"), Rolling: true},
		{Alias: "wolfi", Rolling: true},
		{Alias: "chainguard", Rolling: true},
		{Alias: "secureos", Rolling: true},

		// BellSoft family
		{Alias: "alpaquita", Rolling: true},
		{Alias: "bellsoft-hardened-containers", Rolling: true},

		// others
		{Alias: "archlinux", Rolling: true},
		{Alias: "minimos", Rolling: true},
		{Alias: "arch", ReplacementName: strRef("archlinux"), Rolling: true}, // os-release ID=arch, but namespace uses archlinux
		{Alias: "oracle", ReplacementName: strRef("ol")},                     // non-standard, but common
		{Alias: "oraclelinux", ReplacementName: strRef("ol")},                // non-standard, but common (dockerhub uses "oraclelinux")
		{Alias: "amazon", ReplacementName: strRef("amzn")},                   // non-standard, but common
		{Alias: "amazonlinux", ReplacementName: strRef("amzn")},              // non-standard, but common (dockerhub uses "amazonlinux")
		{Alias: "echo", Rolling: true},
		// TODO: forky is a placeholder for now, but should be updated to sid when the time comes
		// this needs to be automated, but isn't clear how to do so since you'll see things like this:
		//
		// ❯ docker run --rm debian:sid cat /etc/os-release | grep VERSION_CODENAME
		//   VERSION_CODENAME=forky
		// ❯ docker run --rm debian:testing cat /etc/os-release | grep VERSION_CODENAME
		//   VERSION_CODENAME=forky
		//
		// ❯ curl -s http://deb.debian.org/debian/dists/testing/Release | grep '^Codename:'
		//   Codename: forky
		// ❯ curl -s http://deb.debian.org/debian/dists/sid/Release | grep '^Codename:'
		//   Codename: sid
		//
		// depending where the team is during the development cycle you will see different behavior, making automating
		// this a little challenging.
		{Alias: "debian", Codename: "forky", Rolling: true, ReplacementLabelVersion: strRef("unstable")}, // is currently sid, which is considered rolling

		// postmarketOS: map to correct underlying base alpine release version per https://wiki.postmarketos.org/wiki/Releases
		// NOTE: These are not the values as-is from the corresponding /etc/os-release files, these are the values after grype has parsed
		// the raw linux.Release objects from syft into grype Distro objects, so for instance the v prefix on the postmarketos VERSION_ID fields
		// is removed here.

		// edge is specified in the VERSION_ID field pf the /etc/os-release file for postmarketos, and there is no codename; however,
		// to be resilient handle both cases where edge may be parsed as the raw version or as the codename
		{Alias: "postmarketos", Version: "edge", ReplacementName: strRef("alpine"), ReplacementLabelVersion: strRef("edge"), Rolling: true},
		{Alias: "postmarketos", Codename: "edge", ReplacementName: strRef("alpine"), ReplacementLabelVersion: strRef("edge"), Rolling: true},

		{Alias: "postmarketos", Version: "25.12", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("23")},
		{Alias: "postmarketos", Version: "25.06", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("22")},
		{Alias: "postmarketos", Version: "24.12", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("21")},
		{Alias: "postmarketos", Version: "24.06", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("20")},
		{Alias: "postmarketos", Version: "23.12", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("19")},
		{Alias: "postmarketos", Version: "23.06", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("18")},
		{Alias: "postmarketos", Version: "22.12", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("17")},
		{Alias: "postmarketos", Version: "22.06", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("16")},
		{Alias: "postmarketos", Version: "21.12", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("15")},
		{Alias: "postmarketos", Version: "21.06", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("14")},
		{Alias: "postmarketos", Version: "21.03", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("13")},
		{Alias: "postmarketos", Version: "20.05", ReplacementName: strRef("alpine"), ReplacementMajorVersion: strRef("3"), ReplacementMinorVersion: strRef("12")},

		// If no version is specified, map generally to alpine which has same behaviour as today where it matches against all possible
		// alpine releases, otherwise we will get no matches.
		// NOTE: We have to use a hack here with VersionPattern matching empty string because setting Version to "" with no other
		// primary key properties set breaks matching against the above release mappings
		{Alias: "postmarketos", VersionPattern: "^$", ReplacementName: strRef("alpine")},
	}
}

func KnownPackageSpecifierOverrides() []PackageSpecifierOverride {
	// when matching packages, grype will always attempt to do so based off of the package type which means
	// that any request must be in terms of the package type (relative to syft).

	ret := []PackageSpecifierOverride{
		// map all known language ecosystems to their respective syft package types
		{Ecosystem: pkg.Dart.String(), ReplacementEcosystem: ptr(string(pkg.DartPubPkg))},
		{Ecosystem: pkg.Dotnet.String(), ReplacementEcosystem: ptr(string(pkg.DotnetPkg))},
		{Ecosystem: pkg.Elixir.String(), ReplacementEcosystem: ptr(string(pkg.HexPkg))},
		{Ecosystem: pkg.Erlang.String(), ReplacementEcosystem: ptr(string(pkg.HexPkg))},      // Erlang packages use hex.pm, same as Elixir
		{Ecosystem: string(pkg.ErlangOTPPkg), ReplacementEcosystem: ptr(string(pkg.HexPkg))}, // remap erlang-otp to hex for GHSA matching
		{Ecosystem: pkg.Go.String(), ReplacementEcosystem: ptr(string(pkg.GoModulePkg))},
		{Ecosystem: pkg.Haskell.String(), ReplacementEcosystem: ptr(string(pkg.HackagePkg))},
		{Ecosystem: pkg.Java.String(), ReplacementEcosystem: ptr(string(pkg.JavaPkg))},
		{Ecosystem: pkg.JavaScript.String(), ReplacementEcosystem: ptr(string(pkg.NpmPkg))},
		{Ecosystem: pkg.Lua.String(), ReplacementEcosystem: ptr(string(pkg.LuaRocksPkg))},
		{Ecosystem: pkg.OCaml.String(), ReplacementEcosystem: ptr(string(pkg.OpamPkg))},
		{Ecosystem: pkg.PHP.String(), ReplacementEcosystem: ptr(string(pkg.PhpComposerPkg))},
		{Ecosystem: pkg.Python.String(), ReplacementEcosystem: ptr(string(pkg.PythonPkg))},
		{Ecosystem: pkg.R.String(), ReplacementEcosystem: ptr(string(pkg.Rpkg))},
		{Ecosystem: pkg.Ruby.String(), ReplacementEcosystem: ptr(string(pkg.GemPkg))},
		{Ecosystem: pkg.Rust.String(), ReplacementEcosystem: ptr(string(pkg.RustPkg))},
		{Ecosystem: pkg.Swift.String(), ReplacementEcosystem: ptr(string(pkg.SwiftPkg))},
		{Ecosystem: pkg.Swipl.String(), ReplacementEcosystem: ptr(string(pkg.SwiplPackPkg))},

		// jenkins plugins are a special case since they are always considered to be within the java ecosystem
		{Ecosystem: string(pkg.JenkinsPluginPkg), ReplacementEcosystem: ptr(string(pkg.JavaPkg))},

		// legacy cases
		{Ecosystem: "pecl", ReplacementEcosystem: ptr(string(pkg.PhpPeclPkg))},
		{Ecosystem: "kb", ReplacementEcosystem: ptr(string(pkg.KbPkg))},
		{Ecosystem: "dpkg", ReplacementEcosystem: ptr(string(pkg.DebPkg))},
		{Ecosystem: "apkg", ReplacementEcosystem: ptr(string(pkg.ApkPkg))},
	}

	// remap package URL types to syft package types
	for _, t := range pkg.AllPkgs {
		// these types should never be mapped to
		// jenkins plugin: java-archive supersedes this
		// github action workflow: github-action supersedes this
		switch t {
		case pkg.JenkinsPluginPkg, pkg.GithubActionWorkflowPkg:
			continue
		}

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
