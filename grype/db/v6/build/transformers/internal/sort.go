package internal

import (
	"strings"

	db "github.com/anchore/grype/grype/db/v6"
)

type ByAffectedPackage []db.AffectedPackageHandle

func (a ByAffectedPackage) Len() int      { return len(a) }
func (a ByAffectedPackage) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByAffectedPackage) Less(i, j int) bool {
	return comparePackageHandles(a[i].Package, a[i].OperatingSystem, a[i].BlobValue.Ranges, a[j].Package, a[j].OperatingSystem, a[j].BlobValue.Ranges)
}

type ByUnaffectedPackage []db.UnaffectedPackageHandle

func (a ByUnaffectedPackage) Len() int      { return len(a) }
func (a ByUnaffectedPackage) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByUnaffectedPackage) Less(i, j int) bool {
	return comparePackageHandles(a[i].Package, a[i].OperatingSystem, a[i].BlobValue.Ranges, a[j].Package, a[j].OperatingSystem, a[j].BlobValue.Ranges)
}

// comparePackageHandles orders handles by name, ecosystem, version constraints, then
// operating system. The operating-system tie-breaker is what makes the ordering a TOTAL
// order (and therefore the built database deterministic): a single package+constraint can
// map to many operating_system rows -- most notably the per-minor rows produced by the
// RHEL stream-affinity expansion, which share an identical name/ecosystem/constraint and
// differ only by minor version. Without the tie-breaker those rows compare equal and an
// unstable sort emits them in an arbitrary, run-to-run-varying order.
func comparePackageHandles(pkg1 *db.Package, os1 *db.OperatingSystem, ranges1 []db.Range, pkg2 *db.Package, os2 *db.OperatingSystem, ranges2 []db.Range) bool {
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

	// deterministic tie-breaker on the operating system (major/minor/channel/etc.)
	return operatingSystemSortKey(os1) < operatingSystemSortKey(os2)
}

// operatingSystemSortKey builds a stable comparison key from the OS identity fields. The
// NUL separator keeps field boundaries unambiguous so distinct field splits never collide.
func operatingSystemSortKey(os *db.OperatingSystem) string {
	if os == nil {
		return ""
	}
	return strings.Join([]string{
		os.Name,
		os.ReleaseID,
		os.MajorVersion,
		os.MinorVersion,
		os.LabelVersion,
		os.Channel,
		os.Codename,
	}, "\x00")
}
