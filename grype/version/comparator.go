package version

type comparatorGenerator func(constraintUnit) (Comparator, error)

type Comparator interface {
	// Compare compares this version to another version.
	// This returns -1, 0, or 1 if this version is smaller,
	// equal, or larger than the other version, respectively.
	Compare(*Version) (int, error)
}

// type formatAcceptor interface {
//	acceptsFormats() *internal.OrderedSet[Format]
//}

func finalizeComparisonVersion(version *Version, targetFormat Format) (*Version, error) {
	if version == nil {
		return nil, ErrNoVersionProvided
	}
	switch version.Format {
	case targetFormat:
		return version, nil
	case UnknownFormat:
		upgradedVersion, err := NewVersion(version.Raw, targetFormat)
		if err != nil {
			// unable to upgrade the unknown version to the target version
			return nil, newUnsupportedFormatError(targetFormat, version)
		}
		return upgradedVersion, nil
	}

	return nil, newUnsupportedFormatError(targetFormat, version)
}
