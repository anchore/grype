package internal

import v6 "github.com/anchore/grype/internal/db/v6"

type ByAffectedPackage []v6.AffectedPackageHandle

func (a ByAffectedPackage) Len() int      { return len(a) }
func (a ByAffectedPackage) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByAffectedPackage) Less(i, j int) bool {
	if a[i].Package.Name == a[j].Package.Name {
		if a[i].Package.Ecosystem == a[j].Package.Ecosystem {
			for _, b := range a[i].BlobValue.Ranges {
				for _, c := range a[j].BlobValue.Ranges {
					if b.Version.Constraint != c.Version.Constraint {
						return b.Version.Constraint < c.Version.Constraint
					}
				}
			}
		}
		return a[i].Package.Ecosystem < a[j].Package.Ecosystem
	}
	return a[i].Package.Name < a[j].Package.Name
}
