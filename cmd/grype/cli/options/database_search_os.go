package options

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
)

type DBSearchOSs struct {
	OSs   []string        `yaml:"distro" json:"distro" mapstructure:"distro"`
	Specs v6.OSSpecifiers `yaml:"-" json:"-" mapstructure:"-"`
}

func (o *DBSearchOSs) AddFlags(flags clio.FlagSet) {
	// consistent with grype --distro flag today
	flags.StringArrayVarP(&o.OSs, "distro", "", "refine to results with the given operating system (format: 'name', 'name@version', 'name@maj.min', 'name@codename') (supports DB schema v6+ only)")
}

func (o *DBSearchOSs) PostLoad() error {
	if len(o.OSs) == 0 {
		o.Specs = []*v6.OSSpecifier{v6.AnyOSSpecified}
		return nil
	}

	var specs []*v6.OSSpecifier
	for _, osValue := range o.OSs {
		spec, err := parseOSString(osValue)
		if err != nil {
			return err
		}
		if spec != nil {
			spec.AllowMultiple = true
		}
		specs = append(specs, spec)
	}
	o.Specs = specs

	return nil
}

func parseOSString(osValue string) (*v6.OSSpecifier, error) {
	// parse name@version from the distro string
	// version could be a codename, major version, major.minor version, or major.minior.patch version
	switch strings.Count(osValue, ":") {
	case 0:
		// no-op
	case 1:
		// be nice to folks that are close...
		osValue = strings.ReplaceAll(osValue, ":", "@")
	default:
		// this is pretty unexpected
		return nil, fmt.Errorf("invalid distro input provided: %q", osValue)
	}

	parts := strings.Split(osValue, "@")
	switch len(parts) {
	case 1:
		name := strings.TrimSpace(parts[0])
		return &v6.OSSpecifier{Name: name}, nil
	case 2:
		version := strings.TrimSpace(parts[1])
		name := strings.TrimSpace(parts[0])
		if len(version) == 0 {
			return nil, errors.New("invalid distro version provided")
		}

		// parse the version (major.minor.patch, major.minor, major, codename)

		// if starts with a number, then it is a version
		if unicode.IsDigit(rune(version[0])) {
			versionParts := strings.Split(parts[1], ".")
			var major, minor string
			switch len(versionParts) {
			case 1:
				major = versionParts[0]
			case 2:
				major = versionParts[0]
				minor = versionParts[1]
			case 3:
				return nil, fmt.Errorf("invalid distro version provided: patch version ignored: %q", version)
			default:
				return nil, fmt.Errorf("invalid distro version provided: %q", version)
			}

			return &v6.OSSpecifier{Name: name, MajorVersion: major, MinorVersion: minor}, nil
		}

		// is codename / label
		return &v6.OSSpecifier{Name: name, LabelVersion: version}, nil

	default:
		return nil, fmt.Errorf("invalid distro name@version: %q", osValue)
	}
}
