package match

import "github.com/anchore/grype/internal/log"

var explicitIgnoreRules []IgnoreRule

func init() {
	type ignore struct {
		typ   string
		vulns []string
		pkgs  []string
	}

	// Based on https://github.com/anchore/grype/issues/552, which includes a reference to the
	// https://github.com/mergebase/log4j-samples collection, we want to filter these explicitly:
	var explicitIgnores = []ignore{
		{"java-archive",
			[]string{"CVE-2021-44228", "CVE-2021-45046", "GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33"},
			[]string{"log4j-api", "log4j-slf4j-impl", "log4j-to-slf4j", "log4j-1.2-api", "log4j-detector", "log4j-over-slf4j", "slf4j-log4j12"},
		},
	}

	for _, ignoreValues := range explicitIgnores {
		for _, vuln := range ignoreValues.vulns {
			for _, pkg := range ignoreValues.pkgs {
				explicitIgnoreRules = append(explicitIgnoreRules, IgnoreRule{
					Vulnerability: vuln,
					Package: IgnoreRulePackage{
						Name: pkg,
						Type: ignoreValues.typ,
					},
				})
			}
		}
	}
}

// This will filter out matches
func ApplyExplicitIgnoreRules(matches Matches) Matches {
	matches, ignored := ApplyIgnoreRules(matches, explicitIgnoreRules)
	log.Debugf("ignoring explicit matches: %+v", ignored)
	return matches
}
