package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
)

type FixChannelEnabled string

type FixChannels struct {
	// EUS is the Extended Update Support channel for RHEL
	RedHatEUS FixChannel `yaml:"redhat-eus" json:"redhat-eus" mapstructure:"redhat-eus"`
}

type FixChannel struct {
	IDs   []string                 `yaml:"ids" json:"ids" mapstructure:"ids"`       // the list of distro release IDs that this channel applies to
	Apply distro.FixChannelEnabled `yaml:"apply" json:"apply" mapstructure:"apply"` // whether this channel should be applied to the distro when matching
}

func DefaultFixChannels() FixChannels {
	// have CLI defaults in case the API defaults no longer include the the required channels
	rhelEus := FixChannel{
		IDs:   []string{"rhel"}, // this corresponds to the expected value for ID in the /etc/os-release file for RHEL
		Apply: distro.ChannelConditionallyEnabled,
	}

	// use the API defaults
	apiDefaults := distro.DefaultFixChannels()
	for _, channel := range apiDefaults {
		if channel.Name == "eus" {
			rhelEus.Apply = channel.Apply
			rhelEus.IDs = channel.IDs
			break
		}
	}

	return FixChannels{
		RedHatEUS: rhelEus,
	}
}

func (o *FixChannels) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.RedHatEUS, `whether to always enable, disable, or automatically detect when to use Red Hat Extended Update Support (EUS) vulnerability data`)
	descriptions.Add(&o.RedHatEUS.IDs, `the set of /etc/os-release IDs that this channel applies to, e.g. "rhel" for Red Hat Enterprise Linux`)
	descriptions.Add(&o.RedHatEUS.Apply, `whether fixes from this channel should be considered, options are "never", "always", or "auto" (conditionally applied based on SBOM data)`)
}
