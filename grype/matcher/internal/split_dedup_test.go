package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/vulnerability"
)

// A direct match and a lower-ranked indirect match via the source rpm (see result.Rank)
// share an ID and namespace; only the direct result is kept, with the indirect result's detail.
func TestKeepMoreSpecificCandidates_PreservesDroppedDetails(t *testing.T) {
	const id = "ELSA-2022-7628"
	const ns = "oracle:distro:oraclelinux:8"

	mkVuln := func() vulnerability.Vulnerability {
		return vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: id, Namespace: ns}}
	}
	directDetail := match.Detail{Type: match.ExactDirectMatch, Matcher: match.RpmMatcher, Confidence: 1.0, SearchedBy: "php-cli"}
	indirectDetail := match.Detail{Type: match.ExactIndirectMatch, Matcher: match.RpmMatcher, Confidence: 1.0, SearchedBy: "php"}

	candidates := result.Set{id: []result.Result{
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln()}, Details: match.Details{directDetail}, Rank: result.Rank{MatchType: match.ExactDirectMatch}},
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln()}, Details: match.Details{indirectDetail}, Rank: result.Rank{MatchType: match.ExactIndirectMatch}},
	}}

	got := keepMoreSpecificCandidates(candidates, result.Set{})

	require.Len(t, got[id], 1, "the less-specific indirect candidate should be dropped")
	survivor := got[id][0]

	assert.ElementsMatch(t, []match.Type{match.ExactDirectMatch, match.ExactIndirectMatch}, survivor.Details.Types())
	assert.Len(t, survivor.Details, 2, "the survivor's own detail must not be duplicated")
}

// A candidate dropped for a higher-ranked not-vulnerable record keeps its detail on the surviving result.
func TestKeepMoreSpecificCandidates_PreservesNAKDroppedDetails(t *testing.T) {
	const id = "CVE-2026-1"
	const nativeNS = "rapidfort:distro:rapidfort-ubuntu:20.4"
	const streamNS = "rapidfort:distro:rapidfort-ubuntu:20.4+rf"

	mkVuln := func(nsp string) vulnerability.Vulnerability {
		return vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: id, Namespace: nsp}}
	}
	streamDetail := match.Detail{Type: match.ExactDirectMatch, Matcher: match.DpkgMatcher, Confidence: 1.0, SearchedBy: "stream"}
	nativeDetail := match.Detail{Type: match.ExactDirectMatch, Matcher: match.DpkgMatcher, Confidence: 1.0, SearchedBy: "native"}

	candidates := result.Set{id: []result.Result{
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln(streamNS)}, Details: match.Details{streamDetail}, Rank: result.Rank{FromSearchRule: true, MatchType: match.ExactDirectMatch}},
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln(nativeNS)}, Details: match.Details{nativeDetail}, Rank: result.Rank{MatchType: match.ExactDirectMatch}},
	}}
	notVulnerable := result.Set{id: []result.Result{
		{ID: id, Vulnerabilities: []vulnerability.Vulnerability{mkVuln(streamNS)}, Details: match.Details{streamDetail}, Rank: result.Rank{FromSearchRule: true, MatchType: match.ExactDirectMatch}},
	}}

	got := keepMoreSpecificCandidates(candidates, notVulnerable)

	require.Len(t, got[id], 1, "the native candidate denied by the more-specific record should be dropped")
	survivor := got[id][0]
	assert.Contains(t, survivor.Details, nativeDetail, "the dropped native candidate's detail must be preserved as evidence")
}

// A self-origin upstream search (same name as the package) is an indirect search (see
// search.BySourcePackage), so the package's own record calling the version fixed outranks it,
// as it outranks any other indirect match in the same stream.
func TestKeepMoreSpecificCandidates_SelfOriginUpstreamRanksBelowOwnRecord(t *testing.T) {
	const id = "CVE-2026-2"
	const ns = "alpine:distro:alpine:3.18"
	vuln := vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: id, Namespace: ns}}
	of := func(kind match.Type) result.Set {
		return result.Set{id: []result.Result{{
			ID:              id,
			Vulnerabilities: []vulnerability.Vulnerability{vuln},
			Details:         match.Details{{Type: kind, Matcher: match.ApkMatcher, Confidence: 1.0}},
			Rank:            result.Rank{MatchType: kind},
		}}}
	}

	assert.Empty(t, keepMoreSpecificCandidates(of(match.ExactIndirectMatch), of(match.ExactDirectMatch)), "the package's own record decides")
	assert.Len(t, keepMoreSpecificCandidates(of(match.ExactDirectMatch), of(match.ExactDirectMatch))[id], 1, "an equally ranked record does not")
}
