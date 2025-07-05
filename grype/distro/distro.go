package distro

import (
	"fmt"
	"strings"

	hashiVer "github.com/hashicorp/go-version"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/linux"
)

// Distro represents a Linux Distribution.
type Distro struct {
	Type     Type
	Version  string // major.minor.patch
	Codename string // in lieu of a version e.g. "fossa" instead of "20.04"
	Channel  string // distinguish between different feeds for fix and vulnerability data, e.g. "eus" for RHEL
	IDLike   []string

	// fields populated in the constructor

	major     string
	minor     string
	remaining string
}

// New creates a new Distro object populated with the given values.
func New(t Type, version, label string, idLikes ...string) *Distro {
	major, minor, remaining, versionWithoutSuffix, channel := parseVersion(version)

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
		Channel:  channel,

		major:     major,
		minor:     minor,
		remaining: remaining,
	}
}

func parseVersion(version string) (major, minor, remaining, versionWithoutSuffix, channel string) {
	if version == "" {
		return "", "", "", "", ""
	}

	versionWithoutSuffix = version
	if strings.Contains(version, "+") {
		vParts := strings.Split(version, "+")
		version = vParts[0]
		versionWithoutSuffix = version
		channel = vParts[1]
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

	return major, minor, remaining, versionWithoutSuffix, channel
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
func FromRelease(linuxRelease *linux.Release) *Distro {
	if linuxRelease == nil {
		return nil
	}
	d, err := NewFromRelease(*linuxRelease)
	if err != nil {
		log.WithFields("error", err).Warn("unable to create distro from linux distribution")
	}
	return d
}

// NewFromRelease creates a new Distro object derived from a syft linux.Release object.
func NewFromRelease(release linux.Release) (*Distro, error) {
	t := TypeFromRelease(release)
	if t == "" {
		return nil, fmt.Errorf("unable to determine distro type")
	}

	var (
		selectedVersion    string
		selectedVersionObj *hashiVer.Version
	)

	for _, version := range []string{release.VersionID, release.Version} {
		if version == "" {
			continue
		}

		var err error
		selectedVersionObj, err = hashiVer.NewVersion(version)
		if err == nil {
			selectedVersion = version
			break
		}
	}

	if selectedVersion == "" {
		selectedVersion = release.VersionID
	}

	d := New(t, selectedVersion, release.VersionCodename, release.IDLike...)

	if release.ExtendedSupport && d.Channel == "" {
		var major int
		if selectedVersionObj != nil {
			segs := selectedVersionObj.Segments()
			if len(segs) > 0 {
				major = segs[0]
			}
		}
		// we can only be using EUS data for RHEL 8+ releases
		if release.ID == "rhel" && major >= 8 {
			d.Channel = "eus"
		}
	}

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

	if d.Channel != "" {
		versionStr += "+" + d.Channel
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
