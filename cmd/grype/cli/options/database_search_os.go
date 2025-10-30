package options

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
)

type DBSearchOSs struct {
	OSs   []string        `yaml:"distro" json:"distro" mapstructure:"distro"`
	Specs v6.OSSpecifiers `yaml:"-" json:"-" mapstructure:"-"`
}

func (o *DBSearchOSs) AddFlags(flags clio.FlagSet) {
	// consistent with grype --distro flag today
	flags.StringArrayVarP(&o.OSs, "distro", "", "refine to results with the given operating system (format: 'name', 'name[-:@]version', 'name[-:@]maj.min', 'name[-:@]codename')")
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
		specs = append(specs, spec)
	}
	o.Specs = specs

	return nil
}

func parseOSString(osValue string) (*v6.OSSpecifier, error) {
	// Check for multiple @ separators in the original input (not allowed)
	if strings.Count(osValue, "@") > 1 {
		return nil, fmt.Errorf("invalid distro name@version: %q", osValue)
	}

	// Use the shared parsing logic from grype/distro package
	name, version := distro.ParseDistroString(osValue)

	if name == "" {
		return nil, fmt.Errorf("invalid distro input provided: %q", osValue)
	}

	// Check if there was a separator but no version (e.g., "ubuntu@")
	// This can be detected by checking if the original string ends with a separator
	originalTrimmed := strings.TrimSpace(osValue)
	if len(originalTrimmed) > 0 && version == "" {
		lastChar := originalTrimmed[len(originalTrimmed)-1]
		if lastChar == '-' || lastChar == ':' || lastChar == '@' {
			return nil, fmt.Errorf("invalid distro version provided")
		}
	}

	// No version specified
	if version == "" {
		return &v6.OSSpecifier{Name: name}, nil
	}

	// parse the version (major.minor, major, or codename)
	// if starts with a number, then it is a version
	if unicode.IsDigit(rune(version[0])) {
		versionParts := strings.Split(version, ".")
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
}
