package version

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/pkg"
)

var _ Comparator = (*Version)(nil)

// ErrUnsupportedVersion is returned when a version string cannot be parsed into a rich version object
// for a known unsupported case (e.g. golang "devel" version).
var ErrUnsupportedVersion = fmt.Errorf("unsupported version value")

type Version struct {
	Raw         string
	Format      Format
	comparators map[Format]Comparator
}

func NewVersion(raw string, format Format) (*Version, error) {
	version := &Version{
		Raw:    raw,
		Format: format,
	}

	return version, nil
}

func NewVersionFromPkg(p pkg.Package) (*Version, error) {
	format := FormatFromPkg(p)

	ver, err := NewVersion(p.Version, format)
	if err != nil {
		return nil, err
	}

	return ver, nil
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
		err = fmt.Errorf("no comparator populated (format=%s)", v.Format)
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
