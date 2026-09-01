package match

// The version a search was made at is not carried by a Detail in its own right: it rides on the
// package version field of whichever SearchedBy parameters the detail holds. That field is doing two
// different jobs depending on who wrote it, which is why reading and writing it go through the named
// functions below rather than through type switches scattered across the matchers.
//
//   - On distro and ecosystem parameters it is the version the search was made at, which is not
//     always the cataloged package's own: an rpm's source-package search deliberately drops the epoch,
//     since sourceRPMs omit epochs even where the binary has one, so records found under the source
//     name are only commensurate with that epoch-less version. Callers that must test a record against
//     the version it was actually found for read it back with SearchedPackageVersion.
//
//   - On CPE parameters it is the cataloged package's version, recorded for the audit trail. A CPE
//     search does not compare against it -- the version it compares against is normalized into terms a
//     CPE can be written in (an apk's -rN build suffix dropped, a JVM update folded in) and is not
//     recorded anywhere. So SearchedPackageVersion deliberately does not read CPE parameters: the value
//     there answers a different question, and treating it as the searched version would compare a
//     record against a version its search never used.

// SearchedPackageVersion returns the version this detail's search was made at, and whether the detail
// records one. See the note above for why CPE details never do.
func (m Detail) SearchedPackageVersion() (string, bool) {
	switch sb := m.SearchedBy.(type) {
	case DistroParameters:
		return sb.Package.Version, sb.Package.Version != ""
	case EcosystemParameters:
		return sb.Package.Version, sb.Package.Version != ""
	}
	return "", false
}

// SearchedPackageVersion returns the version the search behind these details was made at, and whether
// any of them records one. The details of a single record all describe the same search, so the first
// one to name a version answers for the set.
func (m Details) SearchedPackageVersion() (string, bool) {
	for _, d := range m {
		if v, ok := d.SearchedPackageVersion(); ok {
			return v, true
		}
	}
	return "", false
}
