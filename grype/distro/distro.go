package distro

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/stringutil"
	"github.com/anchore/syft/syft/linux"
)

// Distro represents a Linux Distribution.
type Distro struct {
	Type     Type
	Version  string   // major.minor.patch
	Codename string   // in lieu of a version e.g. "fossa" instead of "20.04"
	Channels []string // distinguish between different feeds for fix and vulnerability data, e.g. "eus" for RHEL
	IDLike   []string

	// fields populated in the constructor

	major     string
	minor     string
	remaining string
}

// New creates a new Distro object populated with the given values.
func New(t Type, version, label string, idLikes ...string) *Distro {
	major, minor, remaining, versionWithoutSuffix, channels := parseVersion(version)

	for i := range idLikes {
		typ, ok := IDMapping[strings.TrimSpace(idLikes[i])]
		if ok {
			idLikes[i] = typ.String()
		}
	}

	return &Distro{
		Type:     t,
		Version:  versionWithoutSuffix,
		Codename: label,
		IDLike:   idLikes,
		Channels: channels,

		major:     major,
		minor:     minor,
		remaining: remaining,
	}
}

func parseVersion(version string) (major, minor, remaining, versionWithoutSuffix string, channels []string) {
	if version == "" {
		return "", "", "", "", nil
	}

	versionWithoutSuffix = version
	var channelStr string
	if strings.Contains(version, "+") {
		vParts := strings.SplitN(version, "+", 2)
		version = vParts[0]
		versionWithoutSuffix = version
		channelStr = vParts[1]
	}

	// if starts with a digit, then assume it's a version and extract the major, minor, and remaining versions
	if version[0] >= '0' && version[0] <= '9' {
		// extract the major, minor, and remaining versions
		parts := strings.Split(version, ".")
		if len(parts) > 0 {
			major = parts[0]
			if len(parts) > 1 {
				minor = parts[1]
			}
			if len(parts) > 2 {
				remaining = strings.Join(parts[2:], ".")
			}
		}
	}

	return major, minor, remaining, versionWithoutSuffix, stringutil.SplitOnAny(strings.TrimSpace(channelStr), ",", "+")
}

// ParseDistroString parses a user-provided distro string in the format "name<separator>version"
// where separator can be "-", ":", or "@". It handles the special case of opensuse-leap
// which contains a hyphen in its distro ID. Returns the distro name and version parts.
func ParseDistroString(s string) (name, version string) {
	if s == "" {
		return "", ""
	}

	s = strings.TrimSpace(s)

	// Special handling for opensuse-leap which has a hyphen in its ID
	// Check if it starts with "opensuse-leap" and handle accordingly
	const opensuseLeap = "opensuse-leap"
	if strings.HasPrefix(strings.ToLower(s), opensuseLeap) {
		// Check if there's a separator after "opensuse-leap"
		remaining := s[len(opensuseLeap):]
		if len(remaining) == 0 {
			return opensuseLeap, ""
		}
		// If the next character is a separator, split there
		if remaining[0] == '-' || remaining[0] == ':' || remaining[0] == '@' {
			return opensuseLeap, strings.TrimSpace(remaining[1:])
		}
		// Otherwise, treat the whole thing as the name
		return s, ""
	}

	// Find the first occurrence of any separator
	separators := []string{"-", ":", "@"}
	minIdx := len(s)
	foundSep := ""

	for _, sep := range separators {
		if idx := strings.Index(s, sep); idx != -1 && idx < minIdx {
			minIdx = idx
			foundSep = sep
		}
	}

	if foundSep == "" {
		return s, ""
	}

	return strings.TrimSpace(s[:minIdx]), strings.TrimSpace(s[minIdx+len(foundSep):])
}

// NewFromNameVersion creates a new Distro object derived from the provided name and version
func NewFromNameVersion(name, version string) *Distro {
	var codename string

	// if there are no digits in the version, it is likely a codename
	if !strings.ContainsAny(version, "0123456789") {
		codename = version
		version = ""
	}

	typ := IDMapping[name]
	if typ == "" {
		typ = Type(name)
	}

	return New(typ, version, codename, string(typ))
}

// FromRelease attempts to get a distro from the linux release, only logging any errors
func FromRelease(linuxRelease *linux.Release, channels []FixChannel) *Distro {
	if linuxRelease == nil {
		return nil
	}
	d, err := NewFromRelease(*linuxRelease, channels)
	if err != nil {
		log.WithFields("error", err).Warn("unable to create distro from linux distribution")
	}
	return d
}

// NewFromRelease creates a new Distro object derived from a syft linux.Release object.
func NewFromRelease(release linux.Release, channels []FixChannel) (*Distro, error) {
	t := TypeFromRelease(release)
	if t == "" {
		return nil, fmt.Errorf("unable to determine distro type")
	}

	var (
		selectedVersion    string
		selectedVersionObj *version.Version
	)

	for _, ver := range []string{release.VersionID, release.Version} {
		if ver == "" {
			continue
		}

		selectedVersionObj = version.New(ver, version.SemanticFormat)

		if selectedVersionObj.Validate() == nil {
			selectedVersion = ver
			break
		}
	}

	if selectedVersion == "" {
		selectedVersion = release.VersionID
	}

	d := New(t, selectedVersion, release.VersionCodename, release.IDLike...)
	d.Channels = applyChannels(release, selectedVersionObj, d.Channels, channels)

	return d, nil
}

func (d Distro) Name() string {
	return string(d.Type)
}

// MajorVersion returns the major version value from the pseudo-semantically versioned distro version value.
func (d Distro) MajorVersion() string {
	return d.major
}

// MinorVersion returns the minor version value from the pseudo-semantically versioned distro version value.
func (d Distro) MinorVersion() string {
	return d.minor
}

func (d Distro) RemainingVersion() string {
	return d.remaining
}

// String returns a human-friendly representation of the Linux distribution.
func (d Distro) String() string {
	return fmt.Sprintf("%s %s", d.ID(), d.VersionString())
}

func (d Distro) ID() string {
	return typeToIDMapping[d.Type]
}

func (d Distro) VersionString() string {
	versionStr := ""
	if d.Version != "" {
		versionStr = d.Version
	} else if d.Codename != "" {
		versionStr = d.Codename
	}

	channels := nonEmptyStrings(d.Channels...)

	if len(channels) > 0 {
		versionStr += "+" + strings.Join(channels, ",")
	}

	return versionStr
}

// Disabled is a way to convey if a Linux distribution is not supported by Grype.
func (d Distro) Disabled() bool {
	switch d.Type {
	case ArchLinux:
		return true
	default:
		return false
	}
}

func nonEmptyStrings(ss ...string) (res []string) {
	for _, s := range ss {
		if s != "" {
			res = append(res, s)
		}
	}
	return res
}
