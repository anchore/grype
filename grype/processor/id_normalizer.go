package processor

import (
	"fmt"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"strings"
)

var _ match.Processor = (*idNormalizer)(nil)

type idNormalizer struct {
	store   store.Store
	enabled bool
}

func NewIDNormalizer(s store.Store, enabled bool) match.Processor {
	return idNormalizer{
		store:   s,
		enabled: enabled,
	}
}

func (a idNormalizer) ProcessMatches(_ pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch) (match.Matches, []match.IgnoredMatch, error) {
	if !a.enabled {
		return matches, ignoredMatches, nil
	}

	var normalizedMatches match.Matches
	for m := range matches.Enumerate() {
		normalizedMatches.Add(normalizeByCVE(a.store, m))
	}

	return normalizedMatches, ignoredMatches, nil
}

func normalizeByCVE(s store.Store, match match.Match) match.Match {
	if isCVE(match.Vulnerability.ID) {
		return match
	}

	var effectiveCVERecordRefs []vulnerability.Reference
	for _, ref := range match.Vulnerability.RelatedVulnerabilities {
		if isCVE(ref.ID) {
			effectiveCVERecordRefs = append(effectiveCVERecordRefs, ref)
			break
		}
	}

	switch len(effectiveCVERecordRefs) {
	case 0:
		log.WithFields(
			"vuln", match.Vulnerability.ID,
			"package", displayPackage(match.Package),
		).Trace("unable to find CVE record for vulnerability, skipping normalization")
		return match
	case 1:
		break
	default:
		log.WithFields(
			"refs", fmt.Sprintf("%+v", effectiveCVERecordRefs),
			"vuln", match.Vulnerability.ID,
			"package", displayPackage(match.Package),
		).Trace("found multiple CVE records for vulnerability, skipping normalization")
		return match
	}

	ref := effectiveCVERecordRefs[0]

	upstreamMetadata, err := s.GetMetadata(ref.ID, ref.Namespace)
	if err != nil {
		log.WithFields("id", ref.ID, "namespace", ref.Namespace, "error", err).Warn("unable to fetch effective CVE metadata")
		return match
	}

	if upstreamMetadata == nil {
		return match
	}

	originalRef := vulnerability.Reference{
		ID:        match.Vulnerability.ID,
		Namespace: match.Vulnerability.Namespace,
	}

	match.Vulnerability.ID = upstreamMetadata.ID
	match.Vulnerability.Namespace = upstreamMetadata.Namespace
	match.Vulnerability.RelatedVulnerabilities = []vulnerability.Reference{originalRef}

	return match
}

func isCVE(id string) bool {
	return strings.HasPrefix(strings.ToLower(id), "cve-")
}
