package options

import (
	"fmt"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
)

type DistroIdentifiers struct {
	// RapidFort remaps the detected base distro of RapidFort-curated images (identified by image
	// labels) to the rapidfort-* distro identities so their curated vulnerability data is used
	RapidFort DistroIdentifier `yaml:"rapidfort" json:"rapidfort" mapstructure:"rapidfort"`
}

type DistroIdentifier struct {
	// Apply indicates whether the identifier should be applied
	Apply string `yaml:"apply" json:"apply" mapstructure:"apply"`
}

func (o *DistroIdentifier) PostLoad() error {
	if o.Apply == "" {
		o.Apply = string(distro.ChannelConditionallyEnabled)
	}

	switch strings.ToLower(o.Apply) {
	case string(distro.ChannelNeverEnabled), string(distro.ChannelConditionallyEnabled):
		return nil
	default:
		return fmt.Errorf("apply %q valid values are 'never' or 'auto' (applied when source metadata indicates the identifier)", o.Apply)
	}
}

func DefaultDistroIdentifiers() DistroIdentifiers {
	var rapidfort *distro.Identifier
	for _, o := range distro.DefaultIdentifiers() {
		if o.Name == "rapidfort" {
			rapidfort = &o
			break
		}
	}
	if rapidfort == nil {
		panic("default distro identifiers do not contain the rapidfort rule")
	}

	// use API defaults for the CLI configuration
	return DistroIdentifiers{
		RapidFort: DistroIdentifier{
			Apply: string(rapidfort.Apply),
		},
	}
}

func (o *DistroIdentifiers) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.RapidFort, `whether to remap the detected distro of RapidFort-curated images to the rapidfort-specific vulnerability data`)
	descriptions.Add(&o.RapidFort.Apply, `whether the identifier should be applied, options are "never" or "auto" (applied when image labels indicate a RapidFort-curated image)`)
}
