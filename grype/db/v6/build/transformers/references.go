package transformers

import db "github.com/anchore/grype/grype/db/v6"

// DeduplicateReferences removes duplicate references, where two references are considered
// identical if they have the same URL and their normalized, sorted tags are equal
func DeduplicateReferences(references []db.Reference) []db.Reference {
	var result []db.Reference
	seenBefore := make(map[string][]db.Reference)
	for _, ref := range references {
		if _, anySeenRefs := seenBefore[ref.URL]; !anySeenRefs {
			seenBefore[ref.URL] = []db.Reference{ref}
			result = append(result, ref)
			continue
		}
		alreadySeenRefs := seenBefore[ref.URL]
		isDuplicate := false
		// Check if this reference already exists for this URL
		for _, already := range alreadySeenRefs {
			if refsAreEqual(already, ref) {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			seenBefore[ref.URL] = append(seenBefore[ref.URL], ref)
			result = append(result, ref)
		}
	}

	return result
}

func refsAreEqual(a, b db.Reference) bool {
	if a.URL != b.URL {
		return false
	}

	if len(a.Tags) != len(b.Tags) {
		return false
	}

	for i := range a.Tags {
		if a.Tags[i] != b.Tags[i] {
			return false
		}
	}
	return true
}
