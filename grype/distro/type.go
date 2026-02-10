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
	Echo         Type = "echo"
	Windows      Type = "windows"
	Mariner      Type = "mariner"
	Azure        Type = "azurelinux"
	RockyLinux   Type = "rockylinux"
	AlmaLinux    Type = "almalinux"
	Gentoo       Type = "gentoo"
	Wolfi        Type = "wolfi"
	Chainguard   Type = "chainguard"
	MinimOS      Type = "minimos"
	Raspbian     Type = "raspbian"
	Scientific   Type = "scientific"
	SecureOS     Type = "secureos"
	PostmarketOS Type = "postmarketos"
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
	Echo,
	Windows,
	Mariner,
	Azure,
	RockyLinux,
	AlmaLinux,
	Gentoo,
	Wolfi,
	Chainguard,
	MinimOS,
	Raspbian,
	Scientific,
	SecureOS,
	PostmarketOS,
}

// IDMapping maps a distro ID from the /etc/os-release (e.g. like "ubuntu") to a Distro type.
var IDMapping = map[string]Type{
	"debian":        Debian,
	"ubuntu":        Ubuntu,
	"rhel":          RedHat,
	"centos":        CentOS,
	"fedora":        Fedora,
	"alpine":        Alpine,
	"busybox":       Busybox,
	"amzn":          AmazonLinux,
	"ol":            OracleLinux,
	"arch":          ArchLinux,
	"opensuse-leap": OpenSuseLeap,
	"sles":          SLES,
	"photon":        Photon,
	"echo":          Echo,
	"mariner":       Mariner,
	"azurelinux":    Azure,
	"rocky":         RockyLinux,
	"almalinux":     AlmaLinux,
	"gentoo":        Gentoo,
	"wolfi":         Wolfi,
	"chainguard":    Chainguard,
	"minimos":       MinimOS,
	"raspbian":      Raspbian,
	"scientific":    Scientific,
	"secureos":      SecureOS,
	"postmarketos":  PostmarketOS,
}

// aliasTypes maps common aliases to their corresponding Type.
var aliasTypes = map[string]Type{
	"Alpine Linux":     Alpine, // needed for CPE matching (see #2039)
	"windows":          Windows,
	"scientific linux": Scientific, // Scientific linux prior to v7 didn't have an os-release file and syft raises up "scientific linux" as the release id as parsed from /etc/redhat-release
}

var typeToIDMapping = map[Type]string{}

func init() {
	for id, t := range IDMapping {
		if _, ok := typeToIDMapping[t]; ok {
			panic("duplicate Type found for ID: " + id + " with Type: " + string(t))
		}
		typeToIDMapping[t] = id
	}
}

func TypeFromRelease(release linux.Release) Type {
	// first try the release ID
	if t, ok := IDMapping[release.ID]; ok {
		return t
	}

	if t, ok := aliasTypes[release.ID]; ok {
		return t
	}

	// use ID_LIKE as a backup
	for _, l := range release.IDLike {
		if t, ok := IDMapping[l]; ok {
			return t
		}
		if t, ok := aliasTypes[l]; ok {
			return t
		}
	}

	// then try the release name as a fallback
	if t, ok := IDMapping[release.Name]; ok {
		return t
	}

	if t, ok := aliasTypes[release.Name]; ok {
		return t
	}

	return ""
}

// String returns the string representation of the given Linux distribution.
func (t Type) String() string {
	return string(t)
}
