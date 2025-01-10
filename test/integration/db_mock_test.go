package integration

import (
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

func newMockDbProvider() *db.MockProvider {
	return db.NewMockProvider([]vulnerability.Vulnerability{
		// "nvd:cpe": {
		//	"jdk": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-jdk",
				Namespace: "nvd:cpe",
			},
			PackageName: "jdk",
			Constraint:  version.MustGetConstraint("< 1.8.0_401", version.JVMFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", "")},
		},
		//},
		//"libvncserver": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-alpine-libvncserver",
				Namespace: "nvd:cpe",
			},
			PackageName: "libvncserver",
			Constraint:  version.MustGetConstraint("< 0.9.10", version.UnknownFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*", "")},
		},
		//},
		//"my-package": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-bogus-my-package-1",
				Namespace: "nvd:cpe",
			},
			PackageName: "my-package",
			Constraint:  version.MustGetConstraint("< 2.0", version.UnknownFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:a:bogus:my-package:*:*:*:*:*:*:something:*", "")},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-bogus-my-package-2-never-match",
				Namespace: "nvd:cpe",
			},
			PackageName: "my-package",
			Constraint:  version.MustGetConstraint("< 2.0", version.UnknownFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:a:something-wrong:my-package:*:*:*:*:*:*:something:*", "")},
		},
		//	},
		//},
		//"alpine:distro:alpine:3.12": {
		//	"libvncserver": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-alpine-libvncserver",
				Namespace: "alpine:distro:alpine:3.12",
			},
			PackageName: "libvncserver",
			Constraint:  version.MustGetConstraint("< 0.9.10", version.UnknownFormat),
		},
		//},
		//"ko": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-azure-autorest-vuln-false-positive",
				Namespace: "alpine:distro:alpine:3.12",
			},
			PackageName: "ko",
			Constraint:  version.MustGetConstraint("< 0", version.ApkFormat),
		},
		//},
		//"npm-apk-package-with-false-positive": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-npm-false-positive-in-apk-subpackage",
				Namespace: "alpine:distro:alpine:3.12",
			},
			PackageName: "npm-apk-package-with-false-positive",
			Constraint:  version.MustGetConstraint("< 0", version.ApkFormat),
		},
		//	},
		//},
		//"gentoo:distro:gentoo:2.8": {
		//	"app-containers/skopeo": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-gentoo-skopeo",
				Namespace: "gentoo:distro:gentoo:2.8",
			},
			PackageName: "app-containers/skopeo",
			Constraint:  version.MustGetConstraint("< 1.6.0", version.UnknownFormat),
		},
		//	},
		//},
		//"github:language:go": {
		//	"github.com/anchore/coverage": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-coverage-main-module-vuln",
				Namespace: "github:language:go",
			},
			PackageName: "github.com/anchore/coverage",
			Constraint:  version.MustGetConstraint("< 1.4.0", version.UnknownFormat),
		},
		//},
		//"github.com/google/uuid": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-uuid-vuln",
				Namespace: "github:language:go",
			},
			PackageName: "github.com/google/uuid",
			Constraint:  version.MustGetConstraint("< 1.4.0", version.UnknownFormat),
		},
		//},
		//"github.com/azure/go-autorest/autorest": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-azure-autorest-vuln-false-positive",
				Namespace: "github:language:go",
			},
			PackageName: "github.com/azure/go-autorest/autorest",
			Constraint:  version.MustGetConstraint("< 0.11.30", version.UnknownFormat),
		},
		//	},
		//},
		//"github:language:idris": {
		//	"my-package": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-bogus-my-package-2-idris",
				Namespace: "github:language:idris",
			},
			PackageName: "my-package",
			Constraint:  version.MustGetConstraint("< 2.0", version.UnknownFormat),
		},
		//	},
		//},
		//"github:language:javascript": {
		//	"npm": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-javascript-validator",
				Namespace: "github:language:javascript",
			},
			PackageName: "npm",
			Constraint:  version.MustGetConstraint("> 5, < 7.2.1", version.UnknownFormat),
		},
		//},
		//"npm-apk-subpackage-with-false-positive": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-npm-false-positive-in-apk-subpackage",
				Namespace: "github:language:javascript",
			},
			PackageName: "npm-apk-subpackage-with-false-positive",
			Constraint:  version.MustGetConstraint("< 2.0.0", version.UnknownFormat),
		},
		//	},
		//},
		//"github:language:python": {
		//	"pygments": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-python-pygments",
				Namespace: "github:language:python",
			},
			PackageName: "pygments",
			Constraint:  version.MustGetConstraint("< 2.6.2", version.PythonFormat),
		},
		//	},
		//	"my-package": []v5.Vulnerability{},
		//},
		//"github:language:ruby": {
		//	"bundler": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-ruby-bundler",
				Namespace: "github:language:ruby",
			},
			PackageName: "bundler",
			Constraint:  version.MustGetConstraint("> 2.0.0, <= 2.1.4", version.GemFormat),
		},
		//	},
		//},
		//"github:language:java": {
		//	"org.anchore:example-java-app-maven": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-java-example-java-app",
				Namespace: "github:language:java",
			},
			PackageName: "org.anchore:example-java-app-maven",
			Constraint:  version.MustGetConstraint(">= 0.0.1, < 1.2.0", version.UnknownFormat),
		},
		//	},
		//},
		//"github:language:dotnet": {
		//	"awssdk.core": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-dotnet-sample",
				Namespace: "github:language:dotnet",
			},
			PackageName: "awssdk.core",
			Constraint:  version.MustGetConstraint(">= 3.7.0.0, < 3.7.12.0", version.SemanticFormat), // FIXME this was VersionFormat: "dotnet"
		},
		//	},
		//},
		//"github:language:haskell": {
		//	"shellcheck": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-haskell-sample",
				Namespace: "github:language:haskell",
			},
			PackageName: "shellcheck",
			Constraint:  version.MustGetConstraint("< 0.9.0", version.SemanticFormat), // FIXME this was: VersionFormat: "haskell"
		},
		//	},
		//},
		//"github:language:rust": {
		//	"hello-auditable": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-rust-sample-1",
				Namespace: "github:language:rust",
			},
			PackageName: "hello-auditable",
			Constraint:  version.MustGetConstraint("< 0.2.0", version.UnknownFormat),
		},
		//},
		//"auditable": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-rust-sample-2",
				Namespace: "github:language:rust",
			},
			PackageName: "auditable",
			Constraint:  version.MustGetConstraint("< 0.2.0", version.UnknownFormat),
		},
		//	},
		//},
		//"debian:distro:debian:8": {
		//	"apt-dev": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-dpkg-apt",
				Namespace: "debian:distro:debian:8",
			},
			PackageName: "apt-dev",
			Constraint:  version.MustGetConstraint("<= 1.8.2", version.DebFormat), // was: "dpkg"
		},
		//	},
		//},
		//"redhat:distro:redhat:8": {
		//	"dive": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-rpmdb-dive",
				Namespace: "redhat:distro:redhat:8",
			},
			PackageName: "dive",
			Constraint:  version.MustGetConstraint("<= 1.0.42", version.RpmFormat),
		},
		//	},
		//},
		//"msrc:distro:windows:10816": {
		//	"10816": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2016-3333",
				Namespace: "msrc:distro:windows:10816",
			},
			PackageName: "10816",
			Constraint:  version.MustGetConstraint("3200970 || 878787 || base", version.KBFormat),
		},
		//	},
		//},
		//"sles:distro:sles:12.5": {
		//	"dive": []v5.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-rpmdb-dive",
				Namespace: "sles:distro:sles:12.5",
			},
			PackageName: "dive",
			Constraint:  version.MustGetConstraint("<= 1.0.42", version.RpmFormat),
		},
	}...)
}
