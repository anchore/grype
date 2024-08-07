package distro

import (
	"github.com/anchore/syft/syft/linux"
)

// Type represents the different Linux distribution options
type Type string

const (
	// represents the set of supported Linux Distributions

	Debian       Type = "debian"
	Ubuntu       Type = "ubuntu"
	RedHat       Type = "redhat"
	CentOS       Type = "centos"
	Fedora       Type = "fedora"
	Alpine       Type = "alpine"
	Busybox      Type = "busybox"
	AmazonLinux  Type = "amazonlinux"
	OracleLinux  Type = "oraclelinux"
	ArchLinux    Type = "archlinux"
	OpenSuseLeap Type = "opensuseleap"
	SLES         Type = "sles"
	Photon       Type = "photon"
	Windows      Type = "windows"
	Mariner      Type = "mariner"
	Azure        Type = "azurelinux"
	RockyLinux   Type = "rockylinux"
	AlmaLinux    Type = "almalinux"
	Gentoo       Type = "gentoo"
	Wolfi        Type = "wolfi"
	Chainguard   Type = "chainguard"
)

// All contains all Linux distribution options
var All = []Type{
	Debian,
	Ubuntu,
	RedHat,
	CentOS,
	Fedora,
	Alpine,
	Busybox,
	AmazonLinux,
	OracleLinux,
	ArchLinux,
	OpenSuseLeap,
	SLES,
	Photon,
	Windows,
	Mariner,
	Azure,
	RockyLinux,
	AlmaLinux,
	Gentoo,
	Wolfi,
	Chainguard,
}

// IDMapping connects a distro ID like "ubuntu" to a Distro type
var IDMapping = map[string]Type{
	"debian":        Debian,
	"ubuntu":        Ubuntu,
	"rhel":          RedHat,
	"centos":        CentOS,
	"fedora":        Fedora,
	"alpine":        Alpine,
	"Alpine Linux":  Alpine,
	"busybox":       Busybox,
	"amzn":          AmazonLinux,
	"ol":            OracleLinux,
	"arch":          ArchLinux,
	"opensuse-leap": OpenSuseLeap,
	"sles":          SLES,
	"photon":        Photon,
	"windows":       Windows,
	"mariner":       Mariner,
	"azurelinux":    Azure,
	"rocky":         RockyLinux,
	"almalinux":     AlmaLinux,
	"gentoo":        Gentoo,
	"wolfi":         Wolfi,
	"chainguard":    Chainguard,
}

func TypeFromRelease(release linux.Release) Type {
	// first try the release ID
	t, ok := IDMapping[release.ID]
	if ok {
		return t
	}

	// use ID_LIKE as a backup
	for _, l := range release.IDLike {
		if t, ok := IDMapping[l]; ok {
			return t
		}
	}

	// first try the release name as a fallback
	t, ok = IDMapping[release.Name]
	if ok {
		return t
	}

	return ""
}

// String returns the string representation of the given Linux distribution.
func (t Type) String() string {
	return string(t)
}
