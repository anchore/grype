package version

import (
	"errors"
	"fmt"
)

var _ Comparator = (*Version)(nil)

type Version struct {
	Raw         string
	Format      Format
	comparators map[Format]Comparator
	Config      ComparisonConfig
}

// New creates a new Version with the default comparison configuration.
// The default MissingEpochStrategy is "zero" for backward compatibility.
func New(raw string, format Format) *Version {
	return NewWithConfig(raw, format, ComparisonConfig{
		MissingEpochStrategy: "zero",
	})
}

// NewWithConfig creates a new Version with a specific comparison configuration.
// This allows control over how missing epochs are handled during version comparison.
func NewWithConfig(raw string, format Format, cfg ComparisonConfig) *Version {
	return &Version{
		Raw:    raw,
		Format: format,
		Config: cfg,
	}
}

func (v *Version) Validate() error {
	_, err := v.getComparator(v.Format)
	return err
}

//nolint:funlen
func (v *Version) getComparator(format Format) (Comparator, error) {
	if v.comparators == nil {
		v.comparators = make(map[Format]Comparator)
	}
	if comparator, ok := v.comparators[format]; ok {
		return comparator, nil
	}

	var comparator Comparator
	var err error
	switch format {
	case SemanticFormat:
		// not enforcing strict semver here, so that we can parse versions like "v1.0.0", "1.0", or "1.0a", which aren't strictly semver compliant
		comparator, err = newSemanticVersion(v.Raw, false)
	case ApkFormat:
		comparator, err = newApkVersion(v.Raw)
	case BitnamiFormat:
		comparator, err = newBitnamiVersion(v.Raw)
	case DebFormat:
		comparator, err = newDebVersion(v.Raw)
	case GolangFormat:
		comparator, err = newGolangVersion(v.Raw)
	case MavenFormat:
		comparator, err = newMavenVersion(v.Raw)
	case RpmFormat:
		comparator, err = newRpmVersion(v.Raw)
	case PythonFormat:
		comparator, err = newPep440Version(v.Raw)
	case KBFormat:
		comparator = newKBVersion(v.Raw)
	case GemFormat:
		comparator, err = newGemVersion(v.Raw)
	case PortageFormat:
		comparator = newPortageVersion(v.Raw)
	case JVMFormat:
		comparator, err = newJvmVersion(v.Raw)
	case UnknownFormat:
		comparator, err = newFuzzyVersion(v.Raw)
	default:
		err = fmt.Errorf("no comparator available for format %q", v.Format)
	}

	v.comparators[format] = comparator

	return comparator, err
}
func (v Version) String() string {
	return fmt.Sprintf("%s (%s)", v.Raw, v.Format)
}

// Compare compares this version to another version.
// This returns -1, 0, or 1 if this version is smaller,
// equal, or larger than the other version, respectively.
func (v Version) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	var result int
	comparator, err := v.getComparator(v.Format)
	if err == nil {
		// if the package version, v was able to compare without error, return the result
		result, err = comparator.Compare(other)
		if err == nil {
			// no error returned for package version or db version, return the result
			return result, nil
		}
	}
	// we were unable to parse the package or db version as v.Format, try other.Format if they differ
	if v.Format != other.Format {
		originalErr := err
		comparator, err = v.getComparator(other.Format)
		if err == nil {
			result, err = comparator.Compare(other)
			if err == nil {
				return result, nil
			}
		}
		err = errors.Join(originalErr, err)
	}

	// all formats returned error, return all errors
	return 0, fmt.Errorf("unable to compare versions: %v %v due to %w", v, other, err)
}

func (v *Version) Is(op Operator, other *Version) (bool, error) {
	if v == nil {
		return false, fmt.Errorf("cannot evaluate version with nil version")
	}
	if other == nil {
		return false, ErrNoVersionProvided
	}

	comparator, err := v.getComparator(v.Format)
	if err != nil {
		return false, fmt.Errorf("unable to get comparator for %s: %w", v.Format, err)
	}

	result, err := comparator.Compare(other)
	if err != nil {
		return false, fmt.Errorf("unable to compare versions %s and %s: %w", v, other, err)
	}

	switch op {
	case EQ, "":
		return result == 0, nil
	case GT:
		return result > 0, nil
	case LT:
		return result < 0, nil
	case GTE:
		return result >= 0, nil
	case LTE:
		return result <= 0, nil
	}
	return false, fmt.Errorf("unknown operator %s", op)
}
