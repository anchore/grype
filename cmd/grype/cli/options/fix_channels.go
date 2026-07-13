package options

import (
	"fmt"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/version"
)

type FixChannelEnabled string

type FixChannels struct {
	// TODO: in the future we may want to support more channels, as well as have a default-apply value here that can be overridden within each channel configuration

	// EUS is the Extended Update Support channel for RHEL
	RedHatEUS FixChannel `yaml:"redhat-eus" json:"redhat-eus" mapstructure:"redhat-eus"`

	// UbuntuESM is the Extended Security Maintenance (Ubuntu Pro) channel for Ubuntu
	UbuntuESM FixChannel `yaml:"ubuntu-esm" json:"ubuntu-esm" mapstructure:"ubuntu-esm"`
}

type FixChannel struct {
	// Apply indicates how the channel should be applied to the distro
	Apply string `yaml:"apply" json:"apply" mapstructure:"apply"`

	// Versions specifies a constraint string indicating which versions of the distro this channel applies to (e.g. ">= 8.0" for RHEL 8 and above)
	Versions string `yaml:"versions" json:"versions" mapstructure:"versions"`
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
	rhelEUS := distro.DefaultFixChannels().Get("eus")
	if rhelEUS == nil {
		panic("default fix channels do not contain Red Hat EUS channel")
	}

	ubuntuESM := distro.DefaultFixChannels().Get("esm")
	if ubuntuESM == nil {
		panic("default fix channels do not contain Ubuntu ESM channel")
	}

	// use API defaults for the CLI configuration
	return FixChannels{
		RedHatEUS: FixChannel{
			Apply:    string(rhelEUS.Apply),
			Versions: rhelEUS.Versions.Value(),
		},
		UbuntuESM: FixChannel{
			Apply: string(ubuntuESM.Apply),
			// note: esm has a nil Versions constraint (no version window), so do not call .Value() on it
			Versions: constraintValue(ubuntuESM.Versions),
		},
	}
}

// constraintValue returns the string form of a version constraint, tolerating a nil constraint (a channel with no
// version window, such as Ubuntu ESM).
func constraintValue(c version.Constraint) string {
	if c == nil {
		return ""
	}
	return c.Value()
}

func (o *FixChannels) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.RedHatEUS, `whether to always enable, disable, or automatically detect when to use Red Hat Extended Update Support (EUS) vulnerability data`)
	descriptions.Add(&o.RedHatEUS.Apply, `whether fixes from this channel should be considered, options are "never", "always", or "auto" (conditionally applied based on SBOM data)`)
	descriptions.Add(&o.UbuntuESM, `whether to always enable, disable, or automatically detect when to use Ubuntu Extended Security Maintenance (ESM / Ubuntu Pro) vulnerability data`)
	descriptions.Add(&o.UbuntuESM.Apply, `whether fixes from this channel should be considered, options are "never", "always", or "auto" (conditionally applied based on SBOM data)`)
}
