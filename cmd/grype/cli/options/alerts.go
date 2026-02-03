package options

import "github.com/anchore/clio"

// Alerts configures how alerts are generated and displayed.
type Alerts struct {
	// ShowEOLDistroWarnings enables warnings about packages from end-of-life distros
	ShowEOLDistroWarnings bool `yaml:"show-eol-distro-warnings" json:"show-eol-distro-warnings" mapstructure:"show-eol-distro-warnings"`
}

var _ clio.FieldDescriber = (*Alerts)(nil)

func defaultAlerts() Alerts {
	return Alerts{
		ShowEOLDistroWarnings: true,
	}
}

func (a *Alerts) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&a.ShowEOLDistroWarnings, `enable/disable warnings about packages from end-of-life (EOL) distros. When enabled, grype will track and report packages that come from distros that have reached their end-of-life date.`)
}
