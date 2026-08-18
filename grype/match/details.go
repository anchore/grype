package match

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/gohugoio/hashstructure"
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

// ID is a content hash over every field of the detail, empty when the detail cannot be hashed.
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

// Less orders details strongest-first so that Details satisfies sort.Interface.
func (m Details) Less(i, j int) bool {
	return compareDetails(m[i], m[j]) < 0
}

// compareDetails orders two details strongest-first over every field, so that details comparing equal
// are the same evidence.
func compareDetails(a, b Detail) int {
	if c := compareTypes(a.Type, b.Type); c != 0 {
		return c
	}

	if a.Confidence != b.Confidence {
		// higher confidence first
		return cmp.Compare(b.Confidence, a.Confidence)
	}

	if c := strings.Compare(string(a.Matcher), string(b.Matcher)); c != 0 {
		return c
	}

	if c := comparePayloads(a.SearchedBy, b.SearchedBy); c != 0 {
		return c
	}

	return comparePayloads(a.Found, b.Found)
}

// compareTypes orders two match types strongest-first per typeOrder, with unrecognized types last.
func compareTypes(a, b Type) int {
	if a == b {
		return 0
	}

	at, aok := typeOrder[a]
	bt, bok := typeOrder[b]
	switch {
	case aok && bok:
		return cmp.Compare(at, bt)
	case aok:
		return -1
	case bok:
		return 1
	default:
		return strings.Compare(string(a), string(b))
	}
}

// comparePayloads orders two Detail payloads, comparing the payload types known to this package field
// by field and anything else by type name and then formatted value.
func comparePayloads(a, b any) int {
	switch av := a.(type) {
	case CPEParameters:
		if bv, ok := b.(CPEParameters); ok {
			return av.compare(bv)
		}
	case CPEResult:
		if bv, ok := b.(CPEResult); ok {
			return av.compare(bv)
		}
	case DistroParameters:
		if bv, ok := b.(DistroParameters); ok {
			return av.compare(bv)
		}
	case DistroResult:
		if bv, ok := b.(DistroResult); ok {
			return av.compare(bv)
		}
	case EcosystemParameters:
		if bv, ok := b.(EcosystemParameters); ok {
			return av.compare(bv)
		}
	case EcosystemResult:
		if bv, ok := b.(EcosystemResult); ok {
			return av.compare(bv)
		}
	}

	// %T is package-qualified and unique per type, so this separates payloads of different types
	if c := strings.Compare(fmt.Sprintf("%T", a), fmt.Sprintf("%T", b)); c != 0 {
		return c
	}

	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}

// compareDetailSets orders two detail sets, the set describing its finding best first.
func compareDetailSets(a, b Details) int {
	return slices.CompareFunc(a, b, compareDetails)
}

func (m Details) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}

// rank returns the typeOrder position of the best detail in a set, counting from 1, with sets holding
// no recognized type ranking last.
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

// mergeDetails returns the union of the given detail sets, deduped and sorted strongest-first, in a
// slice freshly allocated for the caller.
func mergeDetails(sets ...Details) Details {
	var out Details
	for _, set := range sets {
		for _, d := range set {
			out = appendDetail(out, d)
		}
	}
	return sortDetails(out)
}

// appendDetail adds d to out unless out already holds an identical detail, or a CPE detail that d can
// be folded into.
func appendDetail(out Details, d Detail) Details {
	incomingFound, foundIsCPE := d.Found.(CPEResult)
	incomingSearchedBy, searchedByIsCPE := d.SearchedBy.(CPEParameters)
	foldable := foundIsCPE && searchedByIsCPE

	for i := range out {
		if foldable {
			if foldCPEDetail(&out[i], d, incomingSearchedBy, incomingFound) {
				return out
			}
			continue
		}
		if compareDetails(out[i], d) == 0 {
			return out
		}
	}

	return append(out, d)
}

// foldCPEDetail folds an incoming CPE detail into an existing one that found the same record, unioning
// the package CPEs the two were searched by, and reports whether it did.
func foldCPEDetail(existing *Detail, d Detail, incomingSearchedBy CPEParameters, incomingFound CPEResult) bool {
	if existing.Type != d.Type || existing.Matcher != d.Matcher || existing.Confidence != d.Confidence {
		return false
	}

	found, ok := existing.Found.(CPEResult)
	if !ok || !found.Equals(incomingFound) {
		return false
	}

	searchedBy, ok := existing.SearchedBy.(CPEParameters)
	if !ok || searchedBy.Package != incomingSearchedBy.Package {
		return false
	}

	// Merge replaces the CPE list rather than appending to it, so this cannot disturb the given detail
	if err := searchedBy.Merge(incomingSearchedBy); err != nil {
		return false
	}

	existing.SearchedBy = searchedBy
	return true
}

// sortDetails orders details strongest-first, in place, and returns the slice it was given.
func sortDetails(details Details) Details {
	if len(details) < 2 {
		return details
	}

	slices.SortStableFunc(details, compareDetails)
	return details
}
