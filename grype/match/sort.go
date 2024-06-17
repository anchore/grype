package match

import (
	"sort"
	"strings"
)

var _ sort.Interface = (*ByElements)(nil)

type ByElements []Match

// Len is the number of elements in the collection.
func (m ByElements) Len() int {
	return len(m)
}

// Less reports whether the element with index i should sort before the element with index j.
func (m ByElements) Less(i, j int) bool {
	if m[i].Vulnerability.ID == m[j].Vulnerability.ID {
		if m[i].Package.Name == m[j].Package.Name {
			if m[i].Package.Version == m[j].Package.Version {
				if m[i].Package.Type == m[j].Package.Type {
					// this is an approximate ordering, but is not accurate in terms of semver and other version formats
					// but stability is what is important here, not the accuracy of the sort.
					fixVersions1 := m[i].Vulnerability.Fix.Versions
					fixVersions2 := m[j].Vulnerability.Fix.Versions
					sort.Strings(fixVersions1)
					sort.Strings(fixVersions2)
					fixStr1 := strings.Join(fixVersions1, ",")
					fixStr2 := strings.Join(fixVersions2, ",")

					if fixStr1 == fixStr2 {
						loc1 := m[i].Package.Locations.ToSlice()
						loc2 := m[j].Package.Locations.ToSlice()
						var locStr1 string
						for _, location := range loc1 {
							locStr1 += location.RealPath
						}
						var locStr2 string
						for _, location := range loc2 {
							locStr2 += location.RealPath
						}

						return locStr1 < locStr2
					}
					return fixStr1 < fixStr2
				}
				return m[i].Package.Type < m[j].Package.Type
			}
			return m[i].Package.Version < m[j].Package.Version
		}
		return m[i].Package.Name < m[j].Package.Name
	}
	return m[i].Vulnerability.ID < m[j].Vulnerability.ID
}

// Swap swaps the elements with indexes i and j.
func (m ByElements) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}
