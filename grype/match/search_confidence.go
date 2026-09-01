package match

// How confidently a search speaks for the package it was made for is carried by a detail of its own,
// rather than by the confidence of the details that describe the search.
//
// Those confidences say how certain a match of that shape is -- a CPE match is less certain than a
// distro match -- and are fixed per search shape. This is a different question: of the several
// searches made for one package (its own distro rows, a release channel that rebuilt it, an upstream
// it was built from), which one produced this record. Only the caller that made those searches knows
// that, so it says so with a detail of its own and nothing downstream has to infer it from what a
// record looks like.

// SearchConfidence is the SearchedBy payload marking the detail that records that answer. The value
// is Detail.Confidence; this payload is how a reader finds the detail carrying it.
type SearchConfidence struct {
	// Stream names the OS identity the search read -- a release channel, or another vendor's OS
	// rows -- for the audit trail. Empty when the search read the package's own data.
	Stream string `json:"stream,omitempty"`
}

// ConfidenceDetail builds the detail recording how confidently one search speaks for the package.
func ConfidenceDetail(matcher MatcherType, stream string, confidence float64) Detail {
	return Detail{
		Matcher:    matcher,
		SearchedBy: SearchConfidence{Stream: stream},
		Confidence: confidence,
	}
}

// SearchConfidence returns how confidently the search behind these details speaks for the package,
// and whether the set records it at all. A set that does not is not a low-confidence match: it is one
// nobody has ranked, which is why the two cases are distinguishable.
func (m Details) SearchConfidence() (float64, bool) {
	for _, d := range m {
		if _, ok := d.SearchedBy.(SearchConfidence); ok {
			return d.Confidence, true
		}
	}
	return 0, false
}

// WithoutSearchConfidence returns the details without the one recording search confidence, which is
// a matching-time ranking signal rather than evidence for the match. The given set is never modified:
// a detail set is shared by every copy of the record it was found for.
func (m Details) WithoutSearchConfidence() Details {
	if _, ok := m.SearchConfidence(); !ok {
		return m
	}
	out := make(Details, 0, len(m))
	for _, d := range m {
		if _, isConfidence := d.SearchedBy.(SearchConfidence); isConfidence {
			continue
		}
		out = append(out, d)
	}
	return out
}
