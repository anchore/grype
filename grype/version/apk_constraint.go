//nolint:dupl
package version

import "fmt"

type apkConstraint struct {
	raw        string
	expression constraintExpression
}

func newApkConstraint(raw string) (apkConstraint, error) {
	if raw == "" {
		// empty constraints are always satisfied
		return apkConstraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, ApkFormat)
	if err != nil {
		return apkConstraint{}, fmt.Errorf("unable to parse apk constraint phrase: %w", err)
	}

	return apkConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func (c apkConstraint) supported(format Format) bool {
	return format == ApkFormat
}

func (c apkConstraint) Satisfied(version *Version) (bool, error) {
	if c.raw == "" && version != nil {
		// empty constraints are always satisfied
		return true, nil
	}

	if version == nil {
		if c.raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}

		return true, nil
	}

	if !c.supported(version.Format) {
		return false, newUnsupportedFormatError(ApkFormat, version)
	}

	return c.expression.satisfied(version)
}

func (c apkConstraint) String() string {
	if c.raw == "" {
		return "none (apk)"
	}

	return fmt.Sprintf("%s (apk)", c.raw)
}
