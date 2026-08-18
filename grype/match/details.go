package match

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/gohugoio/hashstructure"
	"github.com/scylladb/go-set/strset"
)

type Details []Detail

type Detail struct {
	Type       Type        // The kind of match made (an exact match, fuzzy match, indirect vs direct, etc).
	SearchedBy any         // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	Found      any         // The specific attributes on the vulnerability object that were matched with --this indicates "what" was matched on / within.
	Matcher    MatcherType // The matcher object that discovered the match.
	Confidence float64     // The certainty of the match as a ratio (currently unused, reserved for future use).
}

// String is the string representation of select match fields.
func (m Detail) String() string {
	return fmt.Sprintf("Detail(searchedBy=%q found=%q matcher=%q)", m.SearchedBy, m.Found, m.Matcher)
}

func (m Details) Matchers() (tys []MatcherType) {
	if len(m) == 0 {
		return nil
	}
	for _, d := range m {
		tys = append(tys, d.Matcher)
	}
	return tys
}

func (m Details) Types() (tys []Type) {
	if len(m) == 0 {
		return nil
	}
	for _, d := range m {
		tys = append(tys, d.Type)
	}
	return tys
}

func (m Detail) ID() string {
	f, err := hashstructure.Hash(&m, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%x", f)
}

func (m Details) Len() int {
	return len(m)
}

func (m Details) Less(i, j int) bool {
	a := m[i]
	b := m[j]

	if a.Type != b.Type {
		// exact-direct-match < exact-indirect-match < cpe-match

		at := typeOrder[a.Type]
		bt := typeOrder[b.Type]
		if at == 0 {
			return false
		} else if bt == 0 {
			return true
		}
		return at < bt
	}

	// sort by confidence
	if a.Confidence != b.Confidence {
		// flipped comparison since we want higher confidence to be first
		return a.Confidence > b.Confidence
	}

	// if the types are the same, then sort by the ID (costly, but deterministic)
	return strings.Compare(a.ID(), b.ID()) < 0
}

func (m Details) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}

// rank returns the position of the best match in a detail set, counting from 1, as ordered by
// typeOrder: exact-direct-match (1) beats exact-indirect-match (2) beats cpe-match (3). Lower wins,
// as with any ranking -- a set ranks as well as its best detail. Details with an unrecognized type
// do not contribute, and a set with no recognized type ranks last.
//
// Match.Merge uses this to decide which of two records for the same finding describes it -- the role
// the old direct-supersedes-indirect rules in Matches.Add used to play.
func (m Details) rank() int {
	best := math.MaxInt
	for _, d := range m {
		r, ok := typeOrder[d.Type]
		if !ok {
			continue
		}
		if r < best {
			best = r
		}
	}
	return best
}

// mergeDetails returns the union of the given detail sets, sorted for stable output. Exact
// duplicates are dropped -- both across the sets and within each one, since the same record can be
// reached more than once, and a detail says how the finding was matched, so saying it twice adds
// nothing.
//
// Details are compared by Detail.ID(), a hash over every field, so only wholly identical details
// collapse: two CPE details that searched by different CPEs are both kept. Unlike the other merge
// helpers this cannot key on the value itself -- SearchedBy and Found are `any` and routinely hold
// slice-bearing types (CPEResult.CPEs, EcosystemResult.MatchedSymbols), which are not valid map keys
// and panic on ==.
func mergeDetails(sets ...Details) Details {
	seen := strset.New()
	var out Details
	for _, set := range sets {
		for _, d := range set {
			id := d.ID()
			if seen.Has(id) {
				continue
			}
			seen.Add(id)
			out = append(out, d)
		}
	}
	sort.Sort(out)
	return out
}
