package distro

import "strings"

// LabelMatcher matches a single container image config label by key and value prefix
// (both case-insensitive).
type LabelMatcher struct {
	// Key is the label key to match, e.g. "maintainer"
	Key string

	// ValuePrefix matches any label value that begins with this prefix, e.g. "rapidfort"
	ValuePrefix string
}

// Matches indicates if the given label key/value pair satisfies this matcher.
func (m LabelMatcher) Matches(key, value string) bool {
	return strings.EqualFold(key, m.Key) && strings.HasPrefix(strings.ToLower(value), strings.ToLower(m.ValuePrefix))
}

// Identifier remaps a detected distro to a vendor-specific distro identity when the scanned
// source carries evidence (a marker file in the scanned filesystem or a container image label)
// marking it as a curated derivative of a base distro. Vulnerability data for such images lives
// under a distinct OS name in the DB, so the remapped distro routes matching to that data while
// remaining invisible to clients that do not apply the identifier.
type Identifier struct {
	// Name is the rule identifier used for configuration and logging, e.g. "rapidfort"
	Name string

	// MarkerPaths are file paths whose presence in the scanned source triggers this
	// identifier (e.g. a vendor curation manifest baked into the image filesystem)
	MarkerPaths []string

	// Label is an image label that triggers this identifier (a zero value never matches).
	// Any one trigger (marker path or label) is sufficient.
	Label LabelMatcher

	// DistroIDs maps a detected distro ID (relative to /etc/os-release ID values, e.g. "ubuntu")
	// to the replacement distro ID (e.g. "rapidfort-ubuntu"). Detected distros not present in the
	// map are left unchanged.
	DistroIDs map[string]string

	// Apply indicates whether the identifier should be applied ("auto" applies when the
	// source evidence matches; "never" disables the rule)
	Apply FixChannelEnabled

	// Channels are fix channels to pin on the identified distro (empty means the identified
	// distro queries only channel-less OS records)
	Channels []string
}

// DefaultIdentifiers returns the built-in source-evidence distro identifier rules.
func DefaultIdentifiers() []Identifier {
	return []Identifier{
		{
			Name: "rapidfort",
			// the curation manifest is baked into every RapidFort-curated image and is the
			// primary detection signal; the maintainer label is a secondary signal that also
			// survives SBOM formats which keep image config labels but not file catalogs
			MarkerPaths: []string{"/usr/share/rapidfort/curated.json"},
			Label:       LabelMatcher{Key: "maintainer", ValuePrefix: "rapidfort"},
			DistroIDs: map[string]string{
				"ubuntu": string(RapidFortUbuntu),
				"alpine": string(RapidFortAlpine),
				"debian": string(RapidFortDebian),
				// UBI and clone bases report these IDs; RapidFort publishes all EL-family data
				// under rapidfort-redhat
				"rhel":   string(RapidFortRedHat),
				"centos": string(RapidFortRedHat),
				"fedora": string(RapidFortRedHat),
			},
			Apply: ChannelConditionallyEnabled,
		},
	}
}
