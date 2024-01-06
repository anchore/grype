package processor

import (
	"fmt"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/log"
)

const (
	branch = "├──"
	leaf   = "└──"
)

var _ match.Processor = (*matchLogger)(nil)

type matchLogger struct {
}

func NewMatchLogger() match.Processor {
	return matchLogger{}
}

func (m matchLogger) ProcessMatches(_ pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch) (match.Matches, []match.IgnoredMatch, error) {

	for _, id := range matches.PkgIDs() {
		pkgMatches := matches.GetByPkgID(id)
		if len(pkgMatches) == 0 {
			continue
		}

		logPackageMatches(pkgMatches[0].Package, pkgMatches)
	}

	return matches, ignoredMatches, nil
}

func logPackageMatches(p pkg.Package, matches []match.Match) {
	if len(matches) == 0 {
		return
	}

	log.WithFields("package", displayPackage(p)).Debugf("found %d vulnerabilities", len(matches))
	for idx, m := range matches {
		arm := selectArm(idx, len(matches))
		log.WithFields("vuln", m.Vulnerability.ID, "namespace", m.Vulnerability.Namespace).Debugf("  %s", arm)
	}
}

func displayPackage(p pkg.Package) string {
	if p.PURL != "" {
		return p.PURL
	}
	return fmt.Sprintf("%s@%s (%s)", p.Name, p.Version, p.Type)
}

func selectArm(idx, total int) string {
	if idx == total-1 {
		return leaf
	}
	return branch
}
