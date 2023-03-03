package match

import (
	"github.com/anchore/grype/internal/log"
)

var explicitIgnoreRules []IgnoreRule

func init() {
	type ignoreValues struct {
		typ             string
		vulnerabilities []string
		packages        []string
	}

	var explicitIgnores = []ignoreValues{
		// Based on https://github.com/anchore/grype/issues/552, which includes a reference to the
		// https://github.com/mergebase/log4j-samples collection, we want to filter these explicitly:
		{
			typ:             "java-archive",
			vulnerabilities: []string{"CVE-2021-44228", "CVE-2021-45046", "GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33"},
			packages:        []string{"log4j-api", "log4j-slf4j-impl", "log4j-to-slf4j", "log4j-1.2-api", "log4j-detector", "log4j-over-slf4j", "slf4j-log4j12"},
		},
		// Based on https://github.com/anchore/grype/issues/558:
		{
			typ:             "go-module",
			vulnerabilities: []string{"CVE-2015-5237", "CVE-2021-22570"},
			packages:        []string{"google.golang.org/protobuf"},
		},
		// Affects Squiz Matrix, not in any way related to the matrix ruby gem
		{
			typ:             "gem",
			vulnerabilities: []string{"CVE-2017-14196", "CVE-2017-14197", "CVE-2017-14198", "CVE-2019-19373", "CVE-2019-19374"},
			packages:        []string{"matrix"},
		},
		// Affects the DeleGate proxy server, not in any way related to the delegate ruby gem
		{
			typ:             "gem",
			vulnerabilities: []string{"CVE-1999-1338", "CVE-2001-1202", "CVE-2002-1781", "CVE-2004-0789", "CVE-2004-2003", "CVE-2005-0036", "CVE-2005-0861", "CVE-2006-2072", "CVE-2015-7556"},
			packages:        []string{"delegate"},
		},
		// Affects the Observer autodiscovery PHP/MySQL/SNMP/CDP based network management system, not in any way related to the observer ruby gem
		{
			typ:             "gem",
			vulnerabilities: []string{"CVE-2008-4318"},
			packages:        []string{"observer"},
		},
		// Affects the WeeChat logger plugin, not in any way related to the logger ruby gem
		{
			typ:             "gem",
			vulnerabilities: []string{"CVE-2017-14727"},
			packages:        []string{"logger"},
		},
	}

	for _, ignore := range explicitIgnores {
		for _, vulnerability := range ignore.vulnerabilities {
			for _, packageName := range ignore.packages {
				explicitIgnoreRules = append(explicitIgnoreRules, IgnoreRule{
					Vulnerability: vulnerability,
					Package: IgnoreRulePackage{
						Name: packageName,
						Type: ignore.typ,
					},
				})
			}
		}
	}
}

// ApplyExplicitIgnoreRules Filters out matches meeting the criteria defined above and those within the grype database
func ApplyExplicitIgnoreRules(provider ExclusionProvider, matches Matches) Matches {
	var ignoreRules []IgnoreRule
	ignoreRules = append(ignoreRules, explicitIgnoreRules...)

	for _, m := range matches.Sorted() {
		r, err := provider.GetRules(m.Vulnerability.ID)

		if err != nil {
			log.Warnf("unable to get ignore rules for vuln id=%s", m.Vulnerability.ID)
			continue
		}

		ignoreRules = append(ignoreRules, r...)
	}

	matches, ignored := ApplyIgnoreRules(matches, ignoreRules)

	if len(ignored) > 0 {
		log.Debugf("Removed %d explicit vulnerability matches:", len(ignored))
		for idx, i := range ignored {
			branch := "├──"
			if idx == len(ignored)-1 {
				branch = "└──"
			}
			log.Debugf("  %s %s : %s", branch, i.Match.Vulnerability.ID, i.Package.PURL)
		}
	}

	return matches
}
