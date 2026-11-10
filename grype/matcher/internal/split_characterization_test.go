package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
)

// these tests pin what SplitVulnerable decides today in cases where ranking, the searched package, and
// the searched version interact. Some outcomes are not what the ranking rules alone would give; those
// say so, and a change to the split that flips one should update the assertion on purpose.

// searchedResult is one record as found by one search: the package (and version) searched, and its rank.
func searchedResult(name, ver string, rank result.Rank, v vulnerability.Vulnerability) result.Result {
	p := pkg.Package{ID: pkg.ID(name), Name: name, Version: ver}
	v.PackageName = name
	return result.Result{ID: v.ID, Package: &p, Rank: rank, Vulnerabilities: []vulnerability.Vulnerability{v}}
}

var (
	direct   = result.Rank{MatchType: match.ExactDirectMatch}
	indirect = result.Rank{MatchType: match.ExactIndirectMatch}
)

func TestSet_SplitVulnerable_BinaryAndSourceInOneNamespace(t *testing.T) {
	// a binary's own record calls the version fixed; its source package's record (found through an
	// upstream search, so ranked lower) calls it vulnerable
	const id = "CVE-2026-10"
	split := func(binaryNS, sourceNS string) (result.Set, result.Set) {
		s := result.Set{id: {
			searchedResult("libssl3", "1.1-3", direct, record(id, binaryNS, "< 1.1-1", "1.1-1")),
			searchedResult("openssl", "1.1-3", indirect, record(id, sourceNS, "< 1.1-5", "1.1-5")),
		}}
		return SplitVulnerable(s, debVersion("1.1-3"))
	}

	t.Run("in different namespaces the binary's own record decides", func(t *testing.T) {
		vulnerable, notVulnerable := split(nativeNS, "another:distro:ns:1")

		require.Empty(t, vulnerable)
		require.ElementsMatch(t, []string{nativeNS, "another:distro:ns:1"}, namespacesOf(notVulnerable))
	})

	t.Run("in one namespace the source's covering range sets the binary's fixed record aside", func(t *testing.T) {
		// today: records sharing an ID and namespace with a covering record are set aside before ranking,
		// whatever package they describe, so the lower-ranked source record is reported
		vulnerable, notVulnerable := split(nativeNS, nativeNS)

		require.Len(t, vulnerable[id], 1)
		require.Equal(t, "openssl", vulnerable[id][0].Vulnerabilities[0].PackageName)
		require.Empty(t, notVulnerable)
	})
}

func TestSet_SplitVulnerable_FixedIsJudgedAtTheSplitsVersion(t *testing.T) {
	// one split spans searches at different versions (e.g. an rpm and its epoch-less source). A
	// higher-ranked record searched at 2.0 is outside its range and past its fix there; a lower-ranked
	// record searched at 1.0 covers it.
	const id = "CVE-2026-11"
	s := result.Set{id: {
		searchedResult("pkg-a", "2.0", result.Rank{Priority: 10}, record(id, streamNS, "< 1.5", "1.5")),
		searchedResult("pkg-b", "1.0", result.Rank{}, record(id, nativeNS, "< 1.2", "1.2")),
	}}

	t.Run("called with the lower version, the higher record is not counted as fixed", func(t *testing.T) {
		// today: the range check uses each record's searched version but the fixed check uses the
		// version the split was called with, so 1.0 is not past 1.5 and the lower record decides
		vulnerable, _ := SplitVulnerable(s, debVersion("1.0"))

		require.Equal(t, []string{nativeNS}, namespacesOf(vulnerable))
	})

	t.Run("called with the higher version, the higher record's fix decides", func(t *testing.T) {
		vulnerable, notVulnerable := SplitVulnerable(s, debVersion("2.0"))

		require.Empty(t, vulnerable)
		require.ElementsMatch(t, []string{nativeNS, streamNS}, namespacesOf(notVulnerable))
	})
}

// apkNotAffected is how the DB stores an apk "fixed in 0" record: an affected row satisfied by no
// version, fixed at 0 (the OS transformer writes unaffected rows for other distros only).
func apkNotAffected(id, namespace string) vulnerability.Vulnerability {
	return record(id, namespace, "< 0", "0")
}

func TestSet_SplitVulnerable_ApkNotAffectedRows(t *testing.T) {
	// the apk shape never reaches the split's unaffected handling; it is a fixed record like any other,
	// so it follows the ranking rules for fixed records rather than for unaffected ones
	const id = "CVE-2026-12"
	const otherNS = "another:distro:ns:1"

	t.Run("an equally ranked row does not deny", func(t *testing.T) {
		s := result.Set{id: {
			searchedResult("openssl", "1.1-3", direct, record(id, otherNS, "< 1.1-5", "1.1-5")),
			searchedResult("openssl", "1.1-3", direct, apkNotAffected(id, nativeNS)),
		}}

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1-3"))

		require.Equal(t, []string{otherNS}, namespacesOf(vulnerable))
	})

	t.Run("an equally ranked unaffected record does deny", func(t *testing.T) {
		// the deb/rpm shape of the same statement, for contrast
		s := result.Set{id: {
			searchedResult("openssl", "1.1-3", direct, record(id, otherNS, "< 1.1-5", "1.1-5")),
			searchedResult("openssl", "1.1-3", direct, unaffectedRecord(id, nativeNS, ">= 0")),
		}}

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1-3"))

		require.Empty(t, vulnerable)
	})

	t.Run("a higher ranked row denies", func(t *testing.T) {
		s := result.Set{id: {
			searchedResult("openssl", "1.1-3", indirect, record(id, otherNS, "< 1.1-5", "1.1-5")),
			searchedResult("openssl", "1.1-3", direct, apkNotAffected(id, nativeNS)),
		}}

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1-3"))

		require.Empty(t, vulnerable)
	})

	t.Run("a higher ranked row in the covering record's namespace is set aside", func(t *testing.T) {
		// today: as with any fixed record, sharing an ID and namespace with a covering record sets it aside
		s := result.Set{id: {
			searchedResult("openssl", "1.1-3", indirect, record(id, nativeNS, "< 1.1-5", "1.1-5")),
			searchedResult("openssl", "1.1-3", direct, apkNotAffected(id, nativeNS)),
		}}

		vulnerable, _ := SplitVulnerable(s, debVersion("1.1-3"))

		require.Len(t, vulnerable[id], 1)
	})
}

// ruleStream answers every search with the package's own search plus one search of another package
// name at a rule's priority, keeping the rest of the search's criteria as v6 search rules do.
type ruleStream struct {
	vulnerability.Provider
	name     string
	priority int
}

var _ v6.SearchRuleProvider = ruleStream{}

func (p ruleStream) SearchRewrites(_ pkg.Package, cs []vulnerability.Criteria) ([][]vulnerability.Criteria, bool) {
	var stream []vulnerability.Criteria
	for _, c := range cs {
		if _, ok := c.(*search.PackageNameCriteria); ok {
			c = search.ByPackageName(p.name)
		}
		stream = append(stream, c)
	}
	return [][]vulnerability.Criteria{cs, append(stream, search.ByRule(p.priority))}, true
}

func TestSet_SplitVulnerable_RanksFromSearchRules(t *testing.T) {
	const id = "CVE-2026-13"
	p := pkg.Package{ID: "curl-pkg", Name: "curl", Version: "1.0"}
	stream := func(priority int) ruleStream {
		return ruleStream{
			Provider: mock.VulnerabilityProvider(
				vulnerability.Vulnerability{
					Reference:   vulnerability.Reference{ID: id, Namespace: streamNS},
					PackageName: "rf-curl",
					Constraint:  record(id, streamNS, "< 2.0").Constraint,
				},
				vulnerability.Vulnerability{
					Reference:   vulnerability.Reference{ID: id, Namespace: nativeNS},
					PackageName: "curl",
					Constraint:  record(id, nativeNS, ">= 0").Constraint,
					Unaffected:  true,
				},
			),
			name:     "rf-curl",
			priority: priority,
		}
	}

	for _, priority := range []int{30, -5} {
		found, err := result.NewProvider(stream(priority), p, match.DpkgMatcher).FindAll(search.ByPackageName("curl"))
		require.NoError(t, err)

		ranks := map[string]int{}
		for _, r := range found[id] {
			ranks[r.Vulnerabilities[0].Namespace] = r.Rank.Priority
		}
		require.Equal(t, map[string]int{streamNS: priority, nativeNS: 0}, ranks, "ranks come from the rule's priority")

		// the package's own NAK silences a rule stream ranked below it, but not one that outranks it, and
		// an outranked NAK is not reported as not vulnerable
		vulnerable, notVulnerable := SplitVulnerable(found, debVersion("1.0"))
		if priority > 0 {
			require.Equal(t, []string{streamNS}, namespacesOf(vulnerable), "priority %d", priority)
			require.Empty(t, notVulnerable, "priority %d", priority)
			continue
		}
		require.Empty(t, vulnerable, "priority %d", priority)
		require.ElementsMatch(t, []string{streamNS, nativeNS}, namespacesOf(notVulnerable), "priority %d", priority)
	}
}
