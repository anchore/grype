package version

import (
	"strconv"
	"strings"

	deb "github.com/knqyf263/go-deb-version"
)

var _ Comparator = (*debVersion)(nil)

type debVersion struct {
	obj   deb.Version
	epoch *int // extracted manually since library doesn't export it
	raw   string
}

func newDebVersion(raw string) (debVersion, error) {
	ver, err := deb.NewVersion(raw)
	if err != nil {
		return debVersion{}, invalidFormatError(DebFormat, raw, err)
	}

	// Extract epoch manually for auto strategy support
	epoch := extractDebEpoch(raw)

	return debVersion{
		obj:   ver,
		epoch: epoch,
		raw:   raw,
	}, nil
}

func (v debVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newDebVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	return v.obj.Compare(o.obj), nil
}

// CompareWithConfig compares two deb versions using the provided comparison
// configuration. The config controls behavior for missing epochs:
//   - "zero" strategy: missing epochs are treated as 0
//   - "auto" strategy: missing epochs in the package version match the constraint's epoch
//
// Returns:
//
//	-1 if v < other
//	 0 if v == other
//	 1 if v > other
func (v debVersion) CompareWithConfig(other *Version, cfg ComparisonConfig) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newDebVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	// Handle auto strategy: if package (v) is missing epoch but constraint (other) has one,
	// temporarily inject the constraint's epoch into the package version
	if cfg.MissingEpochStrategy == "auto" {
		if v.epoch == nil && o.epoch != nil {
			// Create a temporary version string with the constraint's epoch
			versionWithEpoch := strconv.Itoa(*o.epoch) + ":" + v.raw
			vWithEpoch, err := deb.NewVersion(versionWithEpoch)
			if err != nil {
				// Fall back to normal comparison if we can't create the modified version
				return normalizeComparison(v.obj.Compare(o.obj)), nil
			}
			return normalizeComparison(vWithEpoch.Compare(o.obj)), nil
		}
	}

	return normalizeComparison(v.obj.Compare(o.obj)), nil
}

// normalizeComparison normalizes a comparison result to -1, 0, or 1
func normalizeComparison(cmp int) int {
	if cmp < 0 {
		return -1
	}
	if cmp > 0 {
		return 1
	}
	return 0
}

// extractDebEpoch extracts the epoch from a Debian version string.
// Returns nil if no epoch is present.
func extractDebEpoch(raw string) *int {
	// Debian version format: [epoch:]upstream_version[-debian_revision]
	// Epoch is optional and separated by a colon
	colonIndex := strings.Index(raw, ":")
	if colonIndex == -1 {
		return nil
	}

	epochStr := raw[:colonIndex]
	epoch, err := strconv.Atoi(epochStr)
	if err != nil {
		return nil
	}

	return &epoch
}
