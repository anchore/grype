package options

import "github.com/anchore/clio"

// Alerts configures how alerts are generated and displayed.
type Alerts struct {
	// EnableEOLDistroWarnings enables warnings about packages from end-of-life distros
	EnableEOLDistroWarnings bool `yaml:"enable-eol-distro-warnings" json:"enable-eol-distro-warnings" mapstructure:"enable-eol-distro-warnings"`
}

var _ clio.FieldDescriber = (*Alerts)(nil)

func defaultAlerts() Alerts {
	return Alerts{
		EnableEOLDistroWarnings: true,
	}
}

func (a *Alerts) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&a.EnableEOLDistroWarnings, `enable/disable warnings about packages from end-of-life (EOL) distros. When enabled, grype will track and report packages that come from distros that have reached their end-of-life date.`)
}
