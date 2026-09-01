package result

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// splitPkg is the package every case in this file is scanned as; only its identity matters.
var splitPkg = pkg.Package{ID: "pkg-1", Name: "openssl", Version: "1.1.1-2rfubu.1"}

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

// confidenceForNamespace ranks a hand-built record the way the confidence on a real record's match
// details ranks it: rows from a release channel speak for this build in particular, everything else
// describes the release the build sits in. A real record's rank is read off the details of the
// search that found it (see confidenceOf); a namespace is the only handle these fixtures have on
// the same fact.
func confidenceForNamespace(namespace string) float64 {
	if i := strings.LastIndex(namespace, ":"); i >= 0 && strings.Contains(namespace[i:], "+") {
		return 1.0
	}
	return 0.5
}

// confidenceDetails is the one match detail a fixture record carries: the confidence the search that
// found it recorded, which is what the split tiers on.
func confidenceDetails(confidence float64) match.Details {
	return match.Details{match.ConfidenceDetail(match.DpkgMatcher, "", confidence)}
}

// setOf puts every record under one entry, the way a single search that turned up several streams'
// rows for one vulnerability does. Each record's tier is derived from the role its namespace implies
// by the same function the matchers use, so these fixtures cannot drift from real ranking.
func setOf(id string, vulns ...vulnerability.Vulnerability) Set {
	var results []Result
	for _, v := range vulns {
		results = append(results, Result{
			ID:              id,
			Package:         &splitPkg,
			Vulnerabilities: []vulnerability.Vulnerability{v},
			Details:         confidenceDetails(confidenceForNamespace(v.Namespace)),
		})
	}
	return Set{id: results}
}

func namespacesOf(s Set) []string {
	var out []string
	for _, v := range s.Vulnerabilities() {
		out = append(out, v.Namespace)
	}
	return out
}

func debVersion(raw string) *version.Version {
	return version.New(raw, version.DebFormat)
}

const (
	nativeNS = "rapidfort:distro:rapidfort-ubuntu:20.4"
	streamNS = "rapidfort:distro:rapidfort-ubuntu:20.4+rf"
)

func TestSet_SplitVulnerable_StreamFixOutranksOpenEndedNativeRow(t *testing.T) {
	// the native rows leave the range open-ended with no fix, but the rebuild's stream shipped one
	// and this build is past it -- the stream that built the package is the one that knows
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, ">= 1.1.1-1ubuntu2"),
		record("CVE-2026-1", streamNS, "< 1.1.1-3rfubu.1", "1.1.1-3rfubu.1"),
	)

	vulnerable, notVulnerable := s.SplitVulnerable(debVersion("1.1.1-5rfubu.1"))

	require.Empty(t, vulnerable)
	require.ElementsMatch(t, []string{nativeNS, streamNS}, namespacesOf(notVulnerable))
}

func TestSet_SplitVulnerable_StreamOutranksNativeWhenBothVulnerable(t *testing.T) {
	// both streams describe this build as vulnerable but name different fixes; only the stream that
	// built it can say which fix actually applies, so the native row it outranks is not reported
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 1.30+dfsg-7ubuntu0.20.04.2", "1.30+dfsg-7ubuntu0.20.04.2"),
		record("CVE-2026-1", streamNS, "< 1.30+dfsg-8rfubu.1", "1.30+dfsg-8rfubu.1"),
	)

	vulnerable, notVulnerable := s.SplitVulnerable(debVersion("1.30+dfsg-7rfubu.1"))

	require.Equal(t, []string{streamNS}, namespacesOf(vulnerable))
	require.Empty(t, notVulnerable, "a vulnerability still being reported must never also become an ignore")
}

func TestSet_SplitVulnerable_SilentStreamFallsThroughToNative(t *testing.T) {
	// the stream's range describes a different release line entirely, so it has nothing to say about
	// this build and the native rows decide
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 1.5", "1.5"),
		record("CVE-2026-1", streamNS, ">= 2.0, < 2.5", "2.5"),
	)

	vulnerable, _ := s.SplitVulnerable(debVersion("1.0"))

	require.Equal(t, []string{nativeNS}, namespacesOf(vulnerable))
}

func TestSet_SplitVulnerable_SilentNativeFallsThroughToStream(t *testing.T) {
	// the mirror: the native row does not cover this build at all, but the stream does
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, ">= 1.1.1-1ubuntu2"),
		record("CVE-2026-1", streamNS, "< 1.1.1-3rfubu.1", "1.1.1-3rfubu.1"),
	)

	vulnerable, _ := s.SplitVulnerable(debVersion("1.1.1-0ubuntu1"))

	require.Equal(t, []string{streamNS}, namespacesOf(vulnerable))
}

func TestSet_SplitVulnerable_OwnWindowsDoNotResolveEachOther(t *testing.T) {
	// one advisory, one stream, one window per release line: the window this build is past says
	// nothing about the window that is still open, and reading the first as "fixed" would drop a
	// real finding
	semver := func(constraint string, fixVersions ...string) vulnerability.Vulnerability {
		v := record("GHSA-1", "github:language:javascript", "< 0", fixVersions...)
		v.Constraint = version.MustGetConstraint(constraint, version.SemanticFormat)
		return v
	}
	s := setOf("GHSA-1",
		semver("< 8.4.1", "8.4.1"),
		semver(">= 9.0.0-beta.1, < 9.2.1", "9.2.1"),
	)

	vulnerable, notVulnerable := s.SplitVulnerable(version.New("9.0.0", version.SemanticFormat))

	require.Len(t, vulnerable.Vulnerabilities(), 1)
	require.Equal(t, ">= 9.0.0-beta.1, < 9.2.1 (semantic)", vulnerable.Vulnerabilities()[0].Constraint.String())
	require.Empty(t, notVulnerable)
}

func TestSet_SplitVulnerable_OutOfRangeWithNoFixIsNotVulnerable(t *testing.T) {
	// a record with no fix recorded at all is still evidence this build is not the vulnerable one;
	// the ignores applied to packages this one owns files for are built from exactly this
	s := setOf("CVE-2026-1", record("CVE-2026-1", nativeNS, "< 1.0"))

	vulnerable, notVulnerable := s.SplitVulnerable(debVersion("1.5"))

	require.Empty(t, vulnerable)
	require.Equal(t, []string{nativeNS}, namespacesOf(notVulnerable))
}

func TestSet_SplitVulnerable_NoVersionRulesNothingOut(t *testing.T) {
	// searching by a CPE that carries no version leaves nothing to compare against, so every record
	// stays a candidate and none can be shown past its fix
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 1.0", "1.0"),
		record("CVE-2026-1", streamNS, "< 2.0", "2.0"),
	)

	for _, v := range []*version.Version{nil, {}} {
		vulnerable, notVulnerable := s.SplitVulnerable(v)

		// the most specific stream still wins; it simply cannot rule anything out
		require.Equal(t, []string{streamNS}, namespacesOf(vulnerable))
		require.Empty(t, notVulnerable)
	}
}

func TestSet_SplitVulnerable_PatchesSearchedByVersionOnVulnerableLeg(t *testing.T) {
	// the searched-by version reaches the match details only through the version filter, and the
	// report asserts it, so the split has to keep doing it
	detail := match.Detail{
		Type:       match.ExactDirectMatch,
		SearchedBy: match.DistroParameters{Package: match.PackageParameter{Name: splitPkg.Name}},
	}
	s := Set{"CVE-2026-1": []Result{{
		ID:              "CVE-2026-1",
		Package:         &splitPkg,
		Details:         match.Details{detail},
		Vulnerabilities: []vulnerability.Vulnerability{record("CVE-2026-1", nativeNS, "< 2.0", "2.0")},
	}}}

	vulnerable, _ := s.SplitVulnerable(debVersion("1.0"))

	searchedBy := vulnerable["CVE-2026-1"][0].Details[0].SearchedBy.(match.DistroParameters)
	require.Equal(t, "1.0", searchedBy.Package.Version)
}

func TestSet_SplitVulnerable_IsStableAcrossCalls(t *testing.T) {
	// results feed match detail ordering, which the report asserts verbatim
	s := setOf("CVE-2026-1",
		record("CVE-2026-1", nativeNS, "< 5.0", "5.0"),
		record("CVE-2026-1", "another:namespace", "< 5.0", "5.0"),
		record("CVE-2026-1", streamNS, "< 5.0", "5.0"),
	)

	first, _ := s.SplitVulnerable(debVersion("1.0"))
	for i := 0; i < 20; i++ {
		next, _ := s.SplitVulnerable(debVersion("1.0"))
		require.Equal(t, first, next)
	}
}

// unaffectedRecord builds one of the provider's unaffected (NAK) records: the vendor saying the
// vulnerability does not apply over the given range.
func unaffectedRecord(id, namespace, constraint string) vulnerability.Vulnerability {
	v := record(id, namespace, constraint)
	v.Unaffected = true
	return v
}

// TestSet_SplitVulnerable_UnaffectedIsNeverAMatch pins that a provider's unaffected record is never
// reported as a finding. The set holds unaffected records alongside affected ones and they carry
// ranges like any other, so only this rule keeps a vendor statement that a package is NOT affected
// out of the vulnerable leg.
func TestSet_SplitVulnerable_UnaffectedIsNeverAMatch(t *testing.T) {
	t.Run("an unaffected record covering the version reports nothing", func(t *testing.T) {
		s := setOf("CVE-1",
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, notVulnerable := s.SplitVulnerable(debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable, "a nak must never surface as a finding")
		require.Len(t, notVulnerable, 1, "and must still reach callers as evidence for ignores")
	})

	t.Run("an unaffected record denies an affected one covering the same version", func(t *testing.T) {
		s := setOf("CVE-1",
			record("CVE-1", nativeNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, _ := s.SplitVulnerable(debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable)
	})

	t.Run("a nak is not ranked against the streams", func(t *testing.T) {
		// the stream is the more specific source and says vulnerable, but "not affected" is not a
		// claim about one release line, so it settles the question wherever it comes from
		s := setOf("CVE-1",
			record("CVE-1", streamNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, ">= 0"),
		)

		vulnerable, _ := s.SplitVulnerable(debVersion("1.1.1-2rfubu.1"))

		require.Empty(t, vulnerable)
	})

	t.Run("an unaffected record that does not cover the version denies nothing", func(t *testing.T) {
		// this is the apk "< 0" NAK shape: satisfied by no version at all. It must not read as a
		// denial here -- callers pick it up from the not-vulnerable leg instead.
		s := setOf("CVE-1",
			record("CVE-1", nativeNS, ">= 0"),
			unaffectedRecord("CVE-1", nativeNS, "< 0"),
		)

		vulnerable, notVulnerable := s.SplitVulnerable(debVersion("1.1.1-2rfubu.1"))

		require.Len(t, vulnerable, 1, "the affected record still stands")
		require.Empty(t, notVulnerable, "the nak is folded into the finding's entry, not reported separately")
	})
}

// TestSet_SplitVulnerable_UsesEachResultsOwnSearchedVersion pins that the split tests each record
// against the version its own search was made with. One split spans a package and its upstreams, and
// an rpm's source-package records are searched at an epoch-less version (see
// rpm.matchUpstreamPackages), so comparing them against the binary's epoch-bearing version is
// invalid.
func TestSet_SplitVulnerable_UsesEachResultsOwnSearchedVersion(t *testing.T) {
	// covers 1.x and nothing at or above 2.0
	resultFor := func(searched string) Result {
		var details []match.Detail
		if searched != "" {
			details = []match.Detail{{
				SearchedBy: match.DistroParameters{
					Package: match.PackageParameter{Name: splitPkg.Name, Version: searched},
				},
			}}
		}
		return Result{
			ID:              "CVE-1",
			Package:         &splitPkg,
			Vulnerabilities: []vulnerability.Vulnerability{record("CVE-1", nativeNS, "< 2.0")},
			Details:         details,
		}
	}

	t.Run("a result inside its own searched version is vulnerable however the split was called", func(t *testing.T) {
		vulnerable, _ := Set{"CVE-1": {resultFor("1.0")}}.SplitVulnerable(debVersion("3.0"))
		require.Len(t, vulnerable, 1, "1.0 < 2.0 at the version this record was searched at")
	})

	t.Run("a result outside its own searched version is not, however the split was called", func(t *testing.T) {
		vulnerable, _ := Set{"CVE-1": {resultFor("3.0")}}.SplitVulnerable(debVersion("1.0"))
		require.Empty(t, vulnerable, "3.0 is past the fix bound at the version this record was searched at")
	})

	t.Run("a result naming no version falls back to the split's", func(t *testing.T) {
		vulnerable, _ := Set{"CVE-1": {resultFor("")}}.SplitVulnerable(debVersion("3.0"))
		require.Empty(t, vulnerable)
	})

	t.Run("results searched at different versions are judged independently in one split", func(t *testing.T) {
		s := Set{"CVE-1": {resultFor("1.0"), resultFor("3.0")}}

		vulnerable, _ := s.SplitVulnerable(nil)

		require.Len(t, vulnerable, 1)
		require.Len(t, vulnerable["CVE-1"], 1, "only the record whose own version is in range survives")
	})
}
