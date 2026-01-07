package internal

import grypeDB "github.com/anchore/grype/grype/db/v6"

type ByAffectedPackage []grypeDB.AffectedPackageHandle

func (a ByAffectedPackage) Len() int      { return len(a) }
func (a ByAffectedPackage) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByAffectedPackage) Less(i, j int) bool {
	return comparePackageHandles(a[i].Package, a[i].BlobValue.Ranges, a[j].Package, a[j].BlobValue.Ranges)
}

type ByUnaffectedPackage []grypeDB.UnaffectedPackageHandle

func (a ByUnaffectedPackage) Len() int      { return len(a) }
func (a ByUnaffectedPackage) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByUnaffectedPackage) Less(i, j int) bool {
	return comparePackageHandles(a[i].Package, a[i].BlobValue.Ranges, a[j].Package, a[j].BlobValue.Ranges)
}

// comparePackageHandles compares two package handles by name, ecosystem, then version constraints
func comparePackageHandles(pkg1 *grypeDB.Package, ranges1 []grypeDB.Range, pkg2 *grypeDB.Package, ranges2 []grypeDB.Range) bool {
	if pkg1.Name != pkg2.Name {
		return pkg1.Name < pkg2.Name
	}
	if pkg1.Ecosystem != pkg2.Ecosystem {
		return pkg1.Ecosystem < pkg2.Ecosystem
	}

	// compare version constraints
	for _, r1 := range ranges1 {
		for _, r2 := range ranges2 {
			if r1.Version.Constraint != r2.Version.Constraint {
				return r1.Version.Constraint < r2.Version.Constraint
			}
		}
	}
	return false
}
