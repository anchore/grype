package internal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// splitPkg states no version, so each split compares its records at the version it is called with
var splitPkg = pkg.Package{ID: "pkg-1", Name: "openssl"}

func debVersion(raw string) *version.Version {
	return version.New(raw, version.DebFormat)
}

const (
	nativeNS = "rapidfort:distro:rapidfort-ubuntu:20.4"
	streamNS = "rapidfort:distro:rapidfort-ubuntu:20.4+rf"
)

const (
	highNS = "rapidfort:distro:rapidfort-ubuntu:20.4+hi"
	lowNS  = "rapidfort:distro:rapidfort-ubuntu:20.4+lo"
)

// prioritized ranks, strongest first: highNS and lowNS as rule streams of priority 30 and 20, streamNS
// as a rule stream of default priority, then the native rows.
func prioritized(id string, vulns ...vulnerability.Vulnerability) result.Set {
	s := setOf(id, vulns...)
	for i, r := range s[id] {
		switch r.Vulnerabilities[0].Namespace {
		case highNS:
			s[id][i].Rank = result.Rank{FromSearchRule: true, RulePriority: 30}
		case lowNS:
			s[id][i].Rank = result.Rank{FromSearchRule: true, RulePriority: 20}
		}
	}
	return s
}

// The highest-ranked record with something to say about the version decides; lower-ranked records
// neither resolve it nor are reported beside it.
func TestSet_SplitVulnerable_HigherRankDecides(t *testing.T) {
	const id = "CVE-2026-1"
	rec := func(namespace, constraint string, fixVersions ...string) vulnerability.Vulnerability {
		return record(id, namespace, constraint, fixVersions...)
	}

	tests := []struct {
		name              string
		records           []vulnerability.Vulnerability
		version           string
		wantVulnerable    []string
		wantNotVulnerable []string
	}{
		{
			name: "a stream's fix resolves an open-ended native row",
			records: []vulnerability.Vulnerability{
				rec(nativeNS, ">= 1.1.1-1ubuntu2"),
				rec(streamNS, "< 1.1.1-3rfubu.1", "1.1.1-3rfubu.1"),
			},
			version:           "1.1.1-5rfubu.1",
			wantNotVulnerable: []string{nativeNS, streamNS},
		},
		{
			name: "a higher-priority rule's fix resolves a lower-priority rule's open-ended row",
			records: []vulnerability.Vulnerability{
				rec(lowNS, ">= 1.0"),
				rec(highNS, "< 1.3", "1.3"),
			},
			version:           "1.4",
			wantNotVulnerable: []string{lowNS, highNS},
		},
		{
			name: "a stream outranks native when both are vulnerable",
			records: []vulnerability.Vulnerability{
				rec(nativeNS, "< 1.30+dfsg-7ubuntu0.20.04.2", "1.30+dfsg-7ubuntu0.20.04.2"),
				rec(streamNS, "< 1.30+dfsg-8rfubu.1", "1.30+dfsg-8rfubu.1"),
			},
			version:        "1.30+dfsg-7rfubu.1",
			wantVulnerable: []string{streamNS},
		},
		{
			name: "only the highest rank is reported when every rank is vulnerable",
			records: []vulnerability.Vulnerability{
				rec(lowNS, "< 1.5", "1.5"),
				rec(highNS, "< 1.3", "1.3"),
				rec(streamNS, "< 1.7", "1.7"),
				rec(nativeNS, "< 1.9", "1.9"),
			},
			version:        "1.0",
			wantVulnerable: []string{highNS},
		},
		{
			name: "a lower rank decides where the higher ranks are silent or absent",
			records: []vulnerability.Vulnerability{
				rec(highNS, ">= 2.0, < 2.5", "2.5"),
				rec(streamNS, "< 1.7", "1.7"),
				rec(nativeNS, "< 1.9", "1.9"),
			},
			version:        "1.0",
			wantVulnerable: []string{streamNS},
		},
		{
			name: "native decides where the stream is silent",
			records: []vulnerability.Vulnerability{
				rec(nativeNS, "< 1.5", "1.5"),
				rec(streamNS, ">= 2.0, < 2.5", "2.5"),
			},
			version:        "1.0",
			wantVulnerable: []string{nativeNS},
		},
		{
			name: "a lower rank's fix does not resolve a higher rank",
			records: []vulnerability.Vulnerability{
				rec(streamNS, "< 1.3", "1.3"),
				rec(highNS, ">= 1.0"),
			},
			version:        "1.4",
			wantVulnerable: []string{highNS},
		},
		{
			name: "native outside its range does not resolve a vulnerable stream",
			records: []vulnerability.Vulnerability{
				rec(nativeNS, ">= 1.1.1-1ubuntu2"),
				rec(streamNS, "< 1.1.1-3rfubu.1", "1.1.1-3rfubu.1"),
			},
			version:        "1.1.1-0ubuntu1",
			wantVulnerable: []string{streamNS},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnerable, notVulnerable := SplitVulnerable(prioritized(id, tt.records...), debVersion(tt.version))

			require.ElementsMatch(t, tt.wantVulnerable, namespacesOf(vulnerable))
			require.ElementsMatch(t, tt.wantNotVulnerable, namespacesOf(notVulnerable))
		})
	}
}

func TestSet_SplitVulnerable_OwnWindowsDoNotResolveEachOther(t *testing.T) {
	// one advisory with one range per release line: being past the first range does not resolve the second
	semver := func(constraint string, fixVersions ...string) vulnerability.Vulnerability {
		v := record("GHSA-1", "github:language:javascript", "< 0", fixVersions...)
		v.Constraint = version.MustGetConstraint(constraint, version.SemanticFormat)
		return v
	}
	s := setOf("GHSA-1",
		semver("< 8.4.1", "8.4.1"),
		semver(">= 9.0.0-beta.1, < 9.2.1", "9.2.1"),
	)

	vulnerable, notVulnerable := SplitVulnerable(s, version.New("9.0.0", version.SemanticFormat))

	require.Len(t, vulnerable.Vulnerabilities(), 1)
	require.Equal(t, ">= 9.0.0-beta.1, < 9.2.1 (semantic)", vulnerable.Vulnerabilities()[0].Constraint.String())
	require.Empty(t, notVulnerable)
}

func TestSet_SplitVulnerable_OutOfRangeWithNoFixIsNotVulnerable(t *testing.T) {
	// ownership ignores are built from records like this
	s := setOf("CVE-2026-1", record("CVE-2026-1", nativeNS, "< 1.0"))

	vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.5"))

	require.Empty(t, vulnerable)
	require.Equal(t, []string{nativeNS}, namespacesOf(notVulnerable))
}

func TestSet_SplitVulnerable_NoVersionRulesNothingOut(t *testing.T) {
	// a CPE search with no version cannot rule any record out
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 1.0", "1.0"),
		record("CVE-2026-1", streamNS, "< 2.0", "2.0"),
	)

	for _, v := range []*version.Version{nil, {}} {
		vulnerable, notVulnerable := SplitVulnerable(s, v)

		require.Equal(t, []string{streamNS}, namespacesOf(vulnerable))
		require.Empty(t, notVulnerable)
	}
}

func TestSet_SplitVulnerable_PatchesSearchedByVersionOnVulnerableLeg(t *testing.T) {
	// the version filter patches the searched-by version onto the match details, which the report asserts
	detail := match.Detail{
		Type:       match.ExactDirectMatch,
		SearchedBy: match.DistroParameters{Package: match.PackageParameter{Name: splitPkg.Name}},
	}
	s := result.Set{"CVE-2026-1": []result.Result{{
		ID:              "CVE-2026-1",
		Package:         &splitPkg,
		Details:         match.Details{detail},
		Vulnerabilities: []vulnerability.Vulnerability{record("CVE-2026-1", nativeNS, "< 2.0", "2.0")},
	}}}

	vulnerable, _ := SplitVulnerable(s, debVersion("1.0"))

	searchedBy := vulnerable["CVE-2026-1"][0].Details[0].SearchedBy.(match.DistroParameters)
	require.Equal(t, "1.0", searchedBy.Package.Version)
}

func TestSet_SplitVulnerable_IsStableAcrossCalls(t *testing.T) {
	// match detail order is derived from this and asserted verbatim in the report
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 5.0", "5.0"),
		record("CVE-2026-1", "another:namespace", "< 5.0", "5.0"),
		record("CVE-2026-1", streamNS, "< 5.0", "5.0"),
	)

	first, _ := SplitVulnerable(s, debVersion("1.0"))
	for i := 0; i < 20; i++ {
		next, _ := SplitVulnerable(s, debVersion("1.0"))
		require.Equal(t, first, next)
	}
}

// unaffectedRecord builds an unaffected (NAK) record over the given range.
func unaffectedRecord(id, namespace, constraint string) vulnerability.Vulnerability {
	v := record(id, namespace, constraint)
	v.Unaffected = true
	return v
}

func TestSet_SplitVulnerable_UnaffectedIsNeverAMatch(t *testing.T) {
	t.Run("an unaffected record covering the version reports nothing", func(t *testing.T) {
		s := setOf("CVE-1",
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable, "a nak must never surface as a finding")
		require.Len(t, notVulnerable, 1, "and must still reach callers as evidence for ignores")
	})

	t.Run("an unaffected record denies an affected one covering the same version", func(t *testing.T) {
		s := setOf("CVE-1",
			record("CVE-1", nativeNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable)
	})

	t.Run("a nak is not ranked against the streams", func(t *testing.T) {
		// a NAK denies regardless of which stream it came from
		s := setOf("CVE-1",
			record("CVE-1", streamNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable)
	})

	t.Run("an unaffected record that does not cover the version denies nothing", func(t *testing.T) {
		// the apk "< 0" NAK shape, satisfied by no version
		s := setOf("CVE-1",
			record("CVE-1", nativeNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, "< 0"),
		)

		vulnerable, notVulnerable := SplitVulnerable(s, debVersion("1.1.1-2rfubu.1"))

		require.Len(t, vulnerable, 1, "the affected record still stands")
		require.Empty(t, notVulnerable, "the nak is folded into the finding's entry, not reported separately")
	})
}

// TestSet_SplitVulnerable_UsesEachResultsOwnPackageVersion: an rpm's source-package records are
// searched at an epoch-less version (see rpm.Matcher.matchDistro), so each record must be compared
// against the version its own search used.
func TestSet_SplitVulnerable_UsesEachResultsOwnPackageVersion(t *testing.T) {
	resultFor := func(searched string) result.Result {
		sp := splitPkg
		sp.Version = searched
		return result.Result{
			ID:              "CVE-1",
			Package:         &sp,
			Vulnerabilities: []vulnerability.Vulnerability{record("CVE-1", nativeNS, "< 2.0")},
		}
	}

	t.Run("a result inside its own searched version is vulnerable however the split was called", func(t *testing.T) {
		vulnerable, _ := SplitVulnerable(result.Set{"CVE-1": {resultFor("1.0")}}, debVersion("3.0"))
		require.Len(t, vulnerable, 1, "1.0 < 2.0 at the version this record was searched at")
	})

	t.Run("a result outside its own searched version is not, however the split was called", func(t *testing.T) {
		vulnerable, _ := SplitVulnerable(result.Set{"CVE-1": {resultFor("3.0")}}, debVersion("1.0"))
		require.Empty(t, vulnerable, "3.0 is past the fix bound at the version this record was searched at")
	})

	t.Run("a result naming no version falls back to the split's", func(t *testing.T) {
		vulnerable, _ := SplitVulnerable(result.Set{"CVE-1": {resultFor("")}}, debVersion("3.0"))
		require.Empty(t, vulnerable)
	})

	t.Run("results searched at different versions are judged independently in one split", func(t *testing.T) {
		s := result.Set{"CVE-1": {resultFor("1.0"), resultFor("3.0")}}

		vulnerable, _ := SplitVulnerable(s, nil)

		require.Len(t, vulnerable, 1)
		require.Len(t, vulnerable["CVE-1"], 1, "only the record whose own version is in range survives")
	})
}

// record builds one hydrated DB record: a single affected range and the fix it names, if any.
func record(id, namespace, constraint string, fixVersions ...string) vulnerability.Vulnerability {
	v := vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: id, Namespace: namespace},
		PackageName: splitPkg.Name,
		Constraint:  version.MustGetConstraint(constraint, version.DebFormat),
	}
	if len(fixVersions) > 0 {
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: fixVersions}
	} else {
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateNotFixed}
	}
	return v
}

// rankForNamespace ranks channel namespaces above the rest, as a real record's stream does (see
// result.Rank).
func rankForNamespace(namespace string) result.Rank {
	if i := strings.LastIndex(namespace, ":"); i >= 0 && strings.Contains(namespace[i:], "+") {
		return result.Rank{FromSearchRule: true}
	}
	return result.Rank{}
}

// setOf puts every record under one ID, ranked by namespace (see rankForNamespace).
func setOf(id string, vulns ...vulnerability.Vulnerability) result.Set {
	var results []result.Result
	for _, v := range vulns {
		results = append(results, result.Result{
			ID:              id,
			Package:         &splitPkg,
			Vulnerabilities: []vulnerability.Vulnerability{v},
			Rank:            rankForNamespace(v.Namespace),
		})
	}
	return result.Set{id: results}
}

func namespacesOf(s result.Set) []string {
	var out []string
	for _, v := range s.Vulnerabilities() {
		out = append(out, v.Namespace)
	}
	return out
}

// withAliases attaches related-vulnerability (alias) IDs to a record.
func withAliases(v vulnerability.Vulnerability, aliases ...string) vulnerability.Vulnerability {
	for _, a := range aliases {
		v.RelatedVulnerabilities = append(v.RelatedVulnerabilities, vulnerability.Reference{ID: a})
	}
	return v
}

func resultOf(v vulnerability.Vulnerability) result.Result {
	return result.Result{
		ID:              v.ID,
		Package:         &splitPkg,
		Vulnerabilities: []vulnerability.Vulnerability{v},
		Rank:            rankForNamespace(v.Namespace),
	}
}

// An advisory fixed exactly at the installed version resolves itself and same-vulnerability rows in
// other namespaces, but not a later advisory that patches additional CVEs (regression: OL8 httpd
// dropped ELSA-2022-7647 because it shares CVE-2022-31813 with the exactly-fixed ELSA-2022-9682).
func TestSet_SplitVulnerable_ExactFixDoesNotEraseBroaderSharedAliasAdvisory(t *testing.T) {
	installed := debVersion("1.0-1")

	exactlyFixed := withAliases(record("ELSA-A", nativeNS, "< 1.0-1", "1.0-1"), "CVE-SHARED")
	broader := withAliases(record("ELSA-B", nativeNS, "< 1.0-2", "1.0-2"), "CVE-SHARED", "CVE-OTHER")

	t.Run("broader still-open advisory survives", func(t *testing.T) {
		s := result.Set{"ELSA-A": {resultOf(exactlyFixed)}, "ELSA-B": {resultOf(broader)}}

		vulnerable, _ := SplitVulnerable(s, installed)

		require.Contains(t, vulnerable, "ELSA-B", "the later advisory patches CVE-OTHER at a build this install has not reached")
		require.NotContains(t, vulnerable, "ELSA-A", "the exactly-fixed advisory is not itself vulnerable")
	})

	t.Run("same-vuln row in another namespace is still resolved", func(t *testing.T) {
		sameVuln := record("CVE-SHARED", "nvd:cpe:cpe", ">= 0")
		s := result.Set{"ELSA-A": {resultOf(exactlyFixed)}, "CVE-SHARED": {resultOf(sameVuln)}}

		vulnerable, _ := SplitVulnerable(s, installed)

		require.NotContains(t, vulnerable, "CVE-SHARED", "exact-fix evidence resolves the same vulnerability across namespaces")
	})

	t.Run("later stream advisory for an already-fixed CVE is suppressed", func(t *testing.T) {
		// installed is exactly the lower stream's fix for CVE-SHARED
		higherStream := withAliases(record("ELSA-C", streamNS, "< 1.0-2", "1.0-2"), "CVE-SHARED")
		s := result.Set{"ELSA-A": {resultOf(exactlyFixed)}, "ELSA-C": {resultOf(higherStream)}}

		vulnerable, _ := SplitVulnerable(s, installed)

		require.NotContains(t, vulnerable, "ELSA-C", "a higher stream's advisory for a CVE already fixed in the installed stream is not vulnerable")
	})
}
