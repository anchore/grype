package match

import (
	"fmt"

	"github.com/mitchellh/hashstructure/v2"
)

type Details []Detail

type Detail struct {
	Type       Type        // The kind of match made (an exact match, fuzzy match, indirect vs direct, etc).
	SearchedBy interface{} // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	Found      interface{} // The specific attributes on the vulnerability object that were matched with --this indicates "what" was matched on / within.
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
	f, err := hashstructure.Hash(&m, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%x", f)
}
