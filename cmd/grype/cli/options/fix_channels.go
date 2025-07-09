package options

import (
	"fmt"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
)

type FixChannelEnabled string

type FixChannels struct {
	// TODO: in the future we may want to support more channels, as well as have a default-apply value here that can be overridden within each channel configuration

	// EUS is the Extended Update Support channel for RHEL
	RedHatEUS FixChannel `yaml:"redhat-eus" json:"redhat-eus" mapstructure:"redhat-eus"`
}

type FixChannel struct {
	Apply string `yaml:"apply" json:"apply" mapstructure:"apply"` // whether this channel should be applied to the distro when matching
}

func (o *FixChannel) PostLoad() error {
	if o.Apply == "" {
		o.Apply = string(distro.ChannelConditionallyEnabled)
	}

	switch strings.ToLower(o.Apply) {
	case string(distro.ChannelNeverEnabled), string(distro.ChannelAlwaysEnabled), string(distro.ChannelConditionallyEnabled):
		return nil
	default:
		return fmt.Errorf("apply %q valid values are 'never', 'always', or 'auto' (conditionally applied based on SBOM data)", o.Apply)
	}
}

func DefaultFixChannels() FixChannels {
	return FixChannels{
		RedHatEUS: FixChannel{
			Apply: string(distro.ChannelConditionallyEnabled),
		},
	}
}

func (o *FixChannels) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.RedHatEUS, `whether to always enable, disable, or automatically detect when to use Red Hat Extended Update Support (EUS) vulnerability data`)
	descriptions.Add(&o.RedHatEUS.Apply, `whether fixes from this channel should be considered, options are "never", "always", or "auto" (conditionally applied based on SBOM data)`)
}
