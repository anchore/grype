package distro

import (
	"fmt"
	"strings"

	hashiVer "github.com/hashicorp/go-version"

	"github.com/anchore/syft/syft/linux"
)

// Distro represents a Linux Distribution.
type Distro struct {
	Type         Type
	Version      *hashiVer.Version
	RawVersion   string
	LabelVersion string
	IDLike       []string
}

// New creates a new Distro object populated with the given values.
func New(t Type, version string, idLikes ...string) (*Distro, error) {
	var verObj *hashiVer.Version
	var err error

	if version != "" {
		verObj, err = hashiVer.NewVersion(version)
		if err != nil {
			return nil, fmt.Errorf("unable to parse version: %w", err)
		}
	}

	return &Distro{
		Type:       t,
		Version:    verObj,
		RawVersion: version,
		IDLike:     idLikes,
	}, nil
}

// NewFromRelease creates a new Distro object derived from a syft linux.Release object.
func NewFromRelease(release linux.Release) (*Distro, error) {
	t := TypeFromRelease(release)
	if t == "" {
		return nil, fmt.Errorf("unable to determine distro type")
	}

	var selectedVersion string
	for _, version := range []string{release.VersionID, release.Version} {
		if version == "" {
			continue
		}

		if _, err := hashiVer.NewVersion(version); err == nil {
			selectedVersion = version
			break
		}
	}

	// already checked hashiVer.NewVersion, this never returns error
	d, _ := New(t, selectedVersion, release.IDLike...)

	switch {
	case d.IsRolling():
		d.LabelVersion = "rolling"
	case isDebianUnstable(t, release):
		d.LabelVersion = "unstable"
	case isAlpineEdge(t, release):
		d.LabelVersion = "edge"
	case selectedVersion == "":
		d.RawVersion = release.Version
	}

	return d, nil
}

func (d Distro) Name() string {
	return string(d.Type)
}

// MajorVersion returns the major version value from the pseudo-semantically versioned distro version value.
func (d Distro) MajorVersion() string {
	if d.Version == nil {
		return strings.Split(d.RawVersion, ".")[0]
	}
	return fmt.Sprintf("%d", d.Version.Segments()[0])
}

// MinorVersion returns the minor version value from the pseudo-semantically versioned distro version value.
func (d Distro) MinorVersion() string {
	if d.Version == nil {
		parts := strings.Split(d.RawVersion, ".")
		if len(parts) > 1 {
			return parts[1]
		}
		return ""
	}
	parts := d.Version.Segments()
	if len(parts) > 1 {
		return fmt.Sprintf("%d", parts[1])
	}
	return ""
}

// FullVersion returns the original user version value.
func (d Distro) FullVersion() string {
	return d.RawVersion
}

// String returns a human-friendly representation of the Linux distribution.
func (d Distro) String() string {
	versionStr := "(version unknown)"
	if d.RawVersion != "" {
		versionStr = d.RawVersion
	}
	return fmt.Sprintf("%s %s", d.Type, versionStr)
}

func (d Distro) IsRolling() bool {
	return d.Type == Wolfi || d.Type == Chainguard || d.Type == ArchLinux || d.Type == Gentoo
}

// Unsupported Linux distributions
func (d Distro) Disabled() bool {
	switch {
	case d.Type == ArchLinux:
		return true
	default:
		return false
	}
}

func isAlpineEdge(t Type, release linux.Release) bool {
	return t == Alpine &&
		(release.Version == "edge" ||
			strings.Contains(release.VersionID, "_alpha") ||
			strings.Contains(release.PrettyName, "edge"))
}

func isDebianUnstable(t Type, release linux.Release) bool {
	return t == Debian &&
		strings.Contains(release.PrettyName, "sid")
}
