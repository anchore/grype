package version

type Comparator interface {
	// Compare compares this version to another version.
	// This returns -1, 0, or 1 if this version is smaller,
	// equal, or larger than the other version, respectively.
	Compare(*Version) (int, error)
}
