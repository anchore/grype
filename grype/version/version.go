package version

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal"
)

var _ Comparator = (*Version)(nil)

// ErrUnsupportedVersion is returned when a version string cannot be parsed into a rich version object
// for a known unsupported case (e.g. golang "devel" version).
var ErrUnsupportedVersion = fmt.Errorf("unsupported version value")

type Version struct {
	Raw        string
	Format     Format
	comparator Comparator
}

func NewVersion(raw string, format Format) (*Version, error) {
	version := &Version{
		Raw:    raw,
		Format: format,
	}

	err := version.populate()
	if err != nil {
		return nil, err
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
func (v *Version) populate() error {
	var comparator Comparator
	var err error
	switch v.Format {
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

	v.comparator = comparator

	return err
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

	if other.Format != v.Format {
		var fmts *internal.OrderedSet[Format]

		if fa, ok := v.comparator.(formatAcceptor); ok {
			fmts = fa.acceptsFormats()
		}
		if fmts.IsEmpty() {
			fmts = internal.NewOrderedSet(v.Format)
		}

		// try to convert to a common format using available formats
		var firstFormatError *UnsupportedComparisonError

		for _, format := range fmts.ToSlice() {
			convertedOther, err := finalizeComparisonVersion(other, format)
			if err == nil {
				other = convertedOther
				firstFormatError = nil // reset the first format error since we successfully converted
				break
			}

			// check if this is a format error (we can try other formats)
			var fmtErr *UnsupportedComparisonError
			if errors.As(err, &fmtErr) {
				if firstFormatError == nil {
					// we want the most preferred format error (the front of the list)
					firstFormatError = fmtErr
				}
				continue // try next format...
			}

			// non-format error...
			return -1, fmt.Errorf("unable to finalize comparison version: %w", err)
		}

		// if we exhausted all formats without success, return the last format error
		if firstFormatError != nil {
			return -1, firstFormatError
		}
	}

	return v.comparator.Compare(other)
}
