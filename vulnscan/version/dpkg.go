package version

import (
	"fmt"
	"strings"

	deb "github.com/knqyf263/go-deb-version"
)

func newDpkgVersion(raw string) (*deb.Version, error) {
	ver, err := deb.NewVersion(raw)
	if err != nil {
		return nil, err
	}
	return &ver, nil
}

// Note: debian/ubuntu uses a "FixedIn" approach, implying that all constraints are "less than" relative to the given version string
type dpkgConstraint struct {
	raw     string
	fixedIn *deb.Version
}

func newDpkgConstraint(raw string) (dpkgConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return dpkgConstraint{}, nil
	}

	fixedVersion := strings.TrimPrefix(strings.TrimSpace(raw), "<")
	if strings.ContainsAny(fixedVersion, "><=") {
		return dpkgConstraint{}, fmt.Errorf("invalid constraint given (%s), only '< fixedversion' allowed for DPKG version constraints", fixedVersion)
	}
	if fixedVersion == raw {
		return dpkgConstraint{}, fmt.Errorf("no constraints found (< operator)")
	}

	fixedIn, err := newDpkgVersion(fixedVersion)
	if err != nil {
		return dpkgConstraint{}, fmt.Errorf("failed to create Dpkg constraint: %w", err)
	}
	return dpkgConstraint{
		raw:     raw,
		fixedIn: fixedIn,
	}, nil
}

func (c dpkgConstraint) supported(format Format) bool {
	return format == DpkgFormat
}

func (c dpkgConstraint) Satisfied(version *Version) (bool, error) {
	if c.raw == "" && version != nil {
		// an empty constraint is always satisfied
		return true, nil
	}

	if !c.supported(version.Format) {
		return false, fmt.Errorf("(dpkg) unsupported format: %s", version.Format)
	}

	if version.rich.dpkgVer == nil {
		return false, fmt.Errorf("no rich dpkg version given: %+v", version)
	}
	return version.rich.dpkgVer.LessThan(*c.fixedIn), nil
}

func (c dpkgConstraint) String() string {
	if c.raw == "" {
		return "[no constraint] (dpkg)"
	}
	return fmt.Sprintf("%s (dpkg)", c.raw)
}
