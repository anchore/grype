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
