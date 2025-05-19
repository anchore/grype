package version

type comparatorGenerator func(constraintUnit) (Comparator, error)

type Comparator interface {
	Compare(*Version) (int, error)
}

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
			return nil, NewUnsupportedFormatError(targetFormat, version.Format)
		}
		return upgradedVersion, nil
	}

	return nil, NewUnsupportedFormatError(targetFormat, version.Format)
}
