package options

import (
	"fmt"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
)

type DistroIdentifiers struct {
	// RapidFort remaps the detected base distro of RapidFort-curated images to the rapidfort-* distros
	RapidFort DistroIdentifier `yaml:"rapidfort" json:"rapidfort" mapstructure:"rapidfort"`
}

type DistroIdentifier struct {
	Apply string `yaml:"apply" json:"apply" mapstructure:"apply"`
}

func (o *DistroIdentifier) PostLoad() error {
	o.Apply = strings.ToLower(o.Apply)
	if o.Apply == "" {
		o.Apply = string(distro.IdentifierAuto)
	}

	switch distro.IdentifierApply(o.Apply) {
	case distro.IdentifierNever, distro.IdentifierAuto:
		return nil
	default:
		return fmt.Errorf("invalid apply value %q: must be 'never' or 'auto'", o.Apply)
	}
}

func DefaultDistroIdentifiers() DistroIdentifiers {
	rapidfort := distro.DefaultIdentifiers().Get(distro.RapidFortIdentifier)
	if rapidfort == nil {
		panic("default distro identifiers do not contain the rapidfort identifier")
	}

	return DistroIdentifiers{
		RapidFort: DistroIdentifier{Apply: string(rapidfort.Apply)},
	}
}

func (o *DistroIdentifiers) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.RapidFort, `remap the detected distro of RapidFort-curated images to RapidFort vulnerability data`)
	descriptions.Add(&o.RapidFort.Apply, `when to apply: "never" or "auto" (when image labels or marker files indicate a RapidFort-curated image)`)
}
