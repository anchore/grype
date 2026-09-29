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
