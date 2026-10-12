package distro

import "strings"

// RapidFortIdentifier is the name of the built-in RapidFort distro identifier.
const RapidFortIdentifier = "rapidfort"

// IdentifierApply says when an Identifier is applied.
type IdentifierApply string

const (
	IdentifierNever IdentifierApply = "never"

	// IdentifierAuto applies the identifier when the source carries its evidence
	IdentifierAuto IdentifierApply = "auto"
)

// LabelMatcher matches a container image label by key and value prefix, both case-insensitive.
type LabelMatcher struct {
	Key         string
	ValuePrefix string
}

func (m LabelMatcher) Matches(key, value string) bool {
	return strings.EqualFold(key, m.Key) && strings.HasPrefix(strings.ToLower(value), strings.ToLower(m.ValuePrefix))
}

// Identifier remaps a detected distro to a vendor distro when the scanned source carries evidence
// (a marker file or an image label) of being the vendor's curated derivative. The vendor's data is
// stored under that distro name.
type Identifier struct {
	// Name identifies the rule in configuration and logs
	Name string

	// MarkerPaths are files whose presence triggers the identifier
	MarkerPaths []string

	// Label is an image label that triggers the identifier; the zero value never matches
	Label LabelMatcher

	// DistroIDs maps a detected os-release ID (e.g. "ubuntu") to its replacement (e.g. "rapidfort-ubuntu")
	DistroIDs map[string]string

	Apply IdentifierApply
}

type Identifiers []Identifier

func (ids Identifiers) Get(name string) *Identifier {
	for i := range ids {
		if strings.EqualFold(ids[i].Name, name) {
			return &ids[i]
		}
	}
	return nil
}

func DefaultIdentifiers() Identifiers {
	return Identifiers{
		{
			Name: RapidFortIdentifier,
			// the label covers SBOMs that keep image labels but not the file catalog
			MarkerPaths: []string{"/usr/share/rapidfort/curated.json"},
			Label:       LabelMatcher{Key: "maintainer", ValuePrefix: "rapidfort"},
			DistroIDs: map[string]string{
				string(Ubuntu): string(RapidFortUbuntu),
				"alpine":       string(RapidFortAlpine),
				"debian":       string(RapidFortDebian),
				// RapidFort publishes all EL-family data under rapidfort-redhat
				rhelOSReleaseID: string(RapidFortRedHat),
				"centos":        string(RapidFortRedHat),
				"fedora":        string(RapidFortRedHat),
			},
			Apply: IdentifierAuto,
		},
	}
}
