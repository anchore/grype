package v6

import (
	"github.com/anchore/syft/syft/pkg"
)

type packageSpecifierLookup struct {
	Package PackageSpecifier
	CPEs    []string
}

// This mapping allows creating affected package handle entries for specific CPEs,
// which allows us to upgrade some CPE-only provider results to more accurate package
// ecosystem matches.  In future this will be another input data source to the grype db
// build process, but this is good enough for now
// nolint:goconst
var CPEPackageSpecifierLookup = buildCPEPackageSpecifierLookup(
	[]packageSpecifierLookup{
		// Anchore Products
		{
			Package: PackageSpecifier{Name: "anchore-enterprise", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:anchore:*:*:*:*:enterprise:*:*:*",
				"cpe:2.3:a:anchore:anchore:*:*:*:*:enterprise:python:*:*",
				"cpe:2.3:a:anchore:anchore_enterprise:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:anchore_enterprise:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:anchore:enterprise:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:enterprise:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "anchore-engine", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:engine:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:engine:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:anchore:anchore_engine:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:anchore_engine:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "vunnel", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:vunnel:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:vunnel:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/anchorectl", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:anchorectl:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:anchorectl:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/k8s-inventory", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:k8s-inventory:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:k8s-inventory:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/ecs-inventory", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:ecs-inventory:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:ecs-inventory:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/syft", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:syft:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:syft:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/grype", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:grype:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:grype:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/grype-db", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:grype-db:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:grype-db:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/stereoscope", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:stereoscope:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:stereoscope:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/quill", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:quill:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:quill:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/grant", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:grant:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:grant:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/anchore/binny", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:binny:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:binny:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "yardstick", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:anchore:yardstick:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:anchore:yardstick:*:*:*:*:*:python:*:*",
			},
		},
		// Atlassian Products
		{
			Package: PackageSpecifier{Name: "com.atlassian.confluence:confluence", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:confluence:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:com.atlassian.confluence:confluence:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.atlassian.confluence:confluence:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "com.atlassian.jira:jira-core", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:jira:*:*:*:*:data_center:*:*:*",
				"cpe:2.3:a:atlassian:jira:*:*:*:*:data_center:maven:*:*",
				"cpe:2.3:a:atlassian:data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:jira_data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira_data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:jira_core_data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira_core_data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:jira_software_data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira_software_data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:jira_server:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira_server:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:com.atlassian.jira:jira-core:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.atlassian.jira:jira-core:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "com.atlassian.bamboo:atlassian-bamboo", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:atlassian:bamboo:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:bamboo:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:bamboo_data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:bamboo_data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:bamboo_server:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:bamboo_server:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:com.atlassian.bamboo:atlassian-bamboo:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.atlassian.bamboo:atlassian-bamboo:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "com.atlassian.bitbucket.server:bitbucket-service-api", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:atlassian:bitbucket_data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:bitbucket_data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:com.atlassian.bitbucket.server:bitbucket-service-api:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.atlassian.bitbucket.server:bitbucket-service-api:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "com.atlassian.jira.plugins:insight-discovery", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:atlassian:assets_discovery_data_center:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:assets_discovery_data_center:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:com.atlassian.jira.plugins:insight-discovery:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:com.atlassian.jira.plugins:insight-discovery:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/hashicorp/consul-k8s/control-plane", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:hashicorp:consul_k8s_control_plane:*:*:*:*:*:go:*:*",
				"cpe:2.3:a:hashicorp:consul-k8s-control-plane:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/hashicorp/consul-template", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:hashicorp:consul_template:*:*:*:*:*:go:*:*",
				"cpe:2.3:a:hashicorp:consul_template:*:*:*:*:*:*:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/hashicorp/go-getter", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:hashicorp:go-getter:*:*:*:*:*:go:*:*",
				"cpe:2.3:a:hashicorp:go-getter:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:hashicorp:go_getter:*:*:*:*:*:go:*:*",
				"cpe:2.3:a:hashicorp:go_getter:*:*:*:*:*:*:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.thrift:libthrift", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.thrift:libthrift:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "github.com/apache/thrift", Ecosystem: string(pkg.GoModulePkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:go:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "ApacheThrift", Ecosystem: string(pkg.DotnetPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:nuget:*:*",
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:.net:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "thrift", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "thrift", Ecosystem: string(pkg.ConanPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:c\\+\\+:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "apache/thrift", Ecosystem: string(pkg.PhpComposerPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:php:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "thrift", Ecosystem: string(pkg.GemPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:ruby:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "Thrift", Ecosystem: string(pkg.CpanPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:perl:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "thrift", Ecosystem: string(pkg.NpmPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:node.js:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "thrift", Ecosystem: string(pkg.RustPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:thrift:*:*:*:*:*:rust:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:tomcat-catalina", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-catalina:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-catalina:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:catalina", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-catalina:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-catalina:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat.embed:tomcat-embed-core", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat.embed:tomcat-embed-core:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-embed-core:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:tomcat-coyote", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-coyote:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-coyote:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:coyote", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-coyote:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-coyote:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:tomcat-coyote-ffm", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-coyote-ffm:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-coyote-ffm:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:coyote-ffm", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-coyote-ffm:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-coyote-ffm:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:tomcat-util", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-util:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-util:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:tomcat-jasper", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-jasper:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-jasper:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:jasper", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-jasper:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-jasper:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat.embed:tomcat-embed-websocket", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat.embed:tomcat-embed-websocket:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-embed-websocket:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "org.apache.tomcat:tomcat-websocket", Ecosystem: string(pkg.JavaPkg)},
			CPEs: []string{
				"cpe:2.3:a:org.apache.tomcat:tomcat-websocket:*:*:*:*:*:maven:*:*",
				"cpe:2.3:a:apache:tomcat-websocket:*:*:*:*:*:maven:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "pyload-ng", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:pyload-ng_project:pyload-ng:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:pyload:pyload:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "cryptography", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:cryptography.io:cryptography:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:cryptography_project:cryptography:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-cryptography_project:python-cryptography:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "picklescan", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:mmaitre314:picklescan:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "tensorflow", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:google:tensorflow:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:tensorflow:tensorflow:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "tensorflow-gpu", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:google:tensorflow-gpu:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:tensorflow:tensorflow-gpu:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "tensorflow-cpu", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:google:tensorflow-cpu:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:tensorflow:tensorflow-cpu:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "django", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:djangoproject:django:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "pillow", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:python:pillow:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "lightning", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:apache:airflow:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "pytorch-lightning", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:lightning_ai:lightning_ai\\/pytorch_lightning:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:lightning_ai:lightning_ai\\/pytorch_lightning:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:lightningai:pytorch_lightning:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:lightningai:pytorch_lightning:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:pytorchlightning:pytorch_lightning:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:pytorchlightning:pytorch_lightning:*:*:*:*:*:*:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "lightning", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:lightning_ai:lightning_ai\\/pytorch_lightning:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:lightning_ai:lightning_ai\\/pytorch_lightning:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:lightningai:pytorch_lightning:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:lightningai:pytorch_lightning:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:pytorchlightning:pytorch_lightning:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:pytorchlightning:pytorch_lightning:*:*:*:*:*:*:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "praisonai", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:praison:praisonai:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "praisonai-platform", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:praison:praisonai-platform:*:*:*:*:*:python:*:*",
			},
		},
		{
			Package: PackageSpecifier{Name: "vllm", Ecosystem: string(pkg.PythonPkg)},
			CPEs: []string{
				"cpe:2.3:a:vllm-project:vllm:*:*:*:*:*:python:*:*",
				"cpe:2.3:a:vllm:vllm:*:*:*:*:*:python:*:*",
			},
		},
	},
)

func buildCPEPackageSpecifierLookup(lookups []packageSpecifierLookup) (lookup map[string][]PackageSpecifier) {
	lookup = make(map[string][]PackageSpecifier, len(lookups))
	for _, l := range lookups {
		for _, cpe := range l.CPEs {
			if _, ok := lookup[cpe]; !ok {
				lookup[cpe] = []PackageSpecifier{}
			}
			lookup[cpe] = append(lookup[cpe], l.Package)
		}
	}

	return lookup
}
