package distro

import (
	"fmt"
	"regexp"
	"strings"

	hashiVer "github.com/hashicorp/go-version"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/linux"
)

// Distro represents a Linux Distribution.
type Distro struct {
	Type     Type
	Version  string
	Codename string
	IDLike   []string

	// fields populated in the constructor

	major     string
	minor     string
	remaining string
}

// New creates a new Distro object populated with the given values.
func New(t Type, version, label string, idLikes ...string) *Distro {
	var major, minor, remaining string
	if version != "" {
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
	}

	for i := range idLikes {
		typ, ok := IDMapping[strings.TrimSpace(idLikes[i])]
		if ok {
			idLikes[i] = typ.String()
		}
	}

	return &Distro{
		Type:      t,
		major:     major,
		minor:     minor,
		remaining: remaining,
		Version:   version,
		Codename:  label,
		IDLike:    idLikes,
	}
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

	var selectedVersion string

	if release.ID == "openEuler" {
		// In the CVE data released by openEuler,
		// the corresponding openEuler version information matches the `Version`
		re := regexp.MustCompile(`\(|\)`)
		selectedVersion = strings.ReplaceAll(re.ReplaceAllString(strings.Trim(release.Version, `"'`), ""), " ", "-")
	} else {
		for _, version := range []string{release.VersionID, release.Version} {
			if version == "" {
				continue
			}

			_, err := hashiVer.NewVersion(version)
			if err == nil {
				selectedVersion = version
				break
			}
		}
	}

	if selectedVersion == "" {
		selectedVersion = release.VersionID
	}

	return New(t, selectedVersion, release.VersionCodename, release.IDLike...), nil
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
	versionStr := "(version unknown)"
	if d.Version != "" {
		versionStr = d.Version
	} else if d.Codename != "" {
		versionStr = d.Codename
	}
	return fmt.Sprintf("%s %s", d.Type, versionStr)
}

// Unsupported Linux distributions
func (d Distro) Disabled() bool {
	switch d.Type {
	case ArchLinux:
		return true
	default:
		return false
	}
}
