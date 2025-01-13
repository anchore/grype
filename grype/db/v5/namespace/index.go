package namespace

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	hashiVer "github.com/anchore/go-version"
	"github.com/anchore/grype/grype/db/v5/namespace/cpe"
	"github.com/anchore/grype/grype/db/v5/namespace/distro"
	"github.com/anchore/grype/grype/db/v5/namespace/language"
	grypeDistro "github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var simpleSemVer = regexp.MustCompile(`^(?P<major>\d+)(\.(?P<minor>\d+)(\.(?P<patch>\d+(?P<remaining>[^-_]+)*))?)?$`)

type Index struct {
	all         []Namespace
	byLanguage  map[syftPkg.Language][]*language.Namespace
	byDistroKey map[string][]*distro.Namespace
	cpe         []*cpe.Namespace
}

func FromStrings(namespaces []string) (*Index, error) {
	all := make([]Namespace, 0)
	byLanguage := make(map[syftPkg.Language][]*language.Namespace)
	byDistroKey := make(map[string][]*distro.Namespace)
	cpeNamespaces := make([]*cpe.Namespace, 0)

	for _, n := range namespaces {
		ns, err := FromString(n)

		if err != nil {
			log.Warnf("unable to create namespace object from namespace=%s: %+v", n, err)
			continue
		}

		all = append(all, ns)

		switch nsObj := ns.(type) {
		case *language.Namespace:
			l := nsObj.Language()
			if _, ok := byLanguage[l]; !ok {
				byLanguage[l] = make([]*language.Namespace, 0)
			}

			byLanguage[l] = append(byLanguage[l], nsObj)
		case *distro.Namespace:
			distroKey := fmt.Sprintf("%s:%s", nsObj.DistroType(), nsObj.Version())
			if _, ok := byDistroKey[distroKey]; !ok {
				byDistroKey[distroKey] = make([]*distro.Namespace, 0)
			}

			byDistroKey[distroKey] = append(byDistroKey[distroKey], nsObj)
		case *cpe.Namespace:
			cpeNamespaces = append(cpeNamespaces, nsObj)
		default:
			log.Warnf("unable to index namespace=%s", n)
			continue
		}
	}

	return &Index{
		all:         all,
		byLanguage:  byLanguage,
		byDistroKey: byDistroKey,
		cpe:         cpeNamespaces,
	}, nil
}

func (i *Index) NamespacesForLanguage(l syftPkg.Language) []*language.Namespace {
	if _, ok := i.byLanguage[l]; ok {
		return i.byLanguage[l]
	}

	return nil
}

//nolint:funlen,gocognit
func (i *Index) NamespacesForDistro(d *grypeDistro.Distro) []*distro.Namespace {
	if d == nil {
		return nil
	}

	dTy := DistroTypeString(d.Type)

	if d.IsRolling() {
		distroKey := fmt.Sprintf("%s:%s", dTy, "rolling")
		if v, ok := i.byDistroKey[distroKey]; ok {
			return v
		}
	}

	var versionSegments []int
	if d.Version != nil {
		versionSegments = d.Version.Segments()
	}

	switch d.Type {
	case grypeDistro.Alpine:
		if v := i.getAlpineMajorMinorNamespace(d, versionSegments); v != nil {
			return v
		}

		// Fall back to alpine:edge if no version segments found
		// alpine:edge is labeled as alpine-x.x_alphaYYYYMMDD
		distroKey := fmt.Sprintf("%s:%s", dTy, "edge")
		if v, ok := i.byDistroKey[distroKey]; ok {
			return v
		}
	case grypeDistro.Debian:
		if v, ok := i.findClosestNamespace(d, versionSegments); ok {
			return v
		}

		if d.RawVersion == "unstable" {
			distroKey := fmt.Sprintf("%s:%s", dTy, "unstable")
			if v, ok := i.byDistroKey[distroKey]; ok {
				return v
			}
		}
	}

	if v, ok := i.findClosestNamespace(d, versionSegments); ok {
		return v
	}

	return nil
}

func (i *Index) getAlpineMajorMinorNamespace(d *grypeDistro.Distro, versionSegments []int) []*distro.Namespace {
	var hasPrerelease bool
	if d.Version != nil {
		hasPrerelease = d.Version.Prerelease() != ""
	}

	if !hasPrerelease {
		namespaces, done := i.findClosestNamespace(d, versionSegments)
		if done {
			return namespaces
		}
	}
	// If the version does not match x.y.z then it is edge
	// In this case it would have - or _ alpha,beta,etc
	// note: later in processing we handle the alpine:edge case
	return nil
}

func (i *Index) findClosestNamespace(d *grypeDistro.Distro, versionSegments []int) ([]*distro.Namespace, bool) {
	ty := DistroTypeString(d.Type)

	// look for exact match
	distroKey := fmt.Sprintf("%s:%s", ty, d.FullVersion())
	if v, ok := i.byDistroKey[distroKey]; ok {
		return v, true
	}

	values := internal.MatchNamedCaptureGroups(simpleSemVer, d.RawVersion)

	switch {
	case values["major"] == "":
		// use edge
		break
	case values["minor"] == "":
		namespaces, done := i.findHighestMatchingMajorVersionNamespaces(d, versionSegments)
		if done {
			return namespaces, true
		}

	default:

		if len(versionSegments) >= 2 {
			// try with only first two version components
			distroKey = fmt.Sprintf("%s:%d.%d", ty, versionSegments[0], versionSegments[1])
			if v, ok := i.byDistroKey[distroKey]; ok {
				return v, true
			}
		}

		if len(versionSegments) >= 1 {
			// try using only major version component
			distroKey = fmt.Sprintf("%s:%d", ty, versionSegments[0])
			if v, ok := i.byDistroKey[distroKey]; ok {
				return v, true
			}
		}
	}
	return nil, false
}

func (i *Index) findHighestMatchingMajorVersionNamespaces(d *grypeDistro.Distro, versionSegments []int) ([]*distro.Namespace, bool) {
	// find the highest version that matches the major version
	majorVersion := versionSegments[0]

	var all []*distro.Namespace
	for _, vs := range i.byDistroKey {
		for _, v := range vs {
			if v.DistroType() == d.Type {
				all = append(all, v)
			}
		}
	}

	type namespaceVersion struct {
		version   *hashiVer.Version
		namespace *distro.Namespace
	}

	var valid []namespaceVersion
	for _, v := range all {
		if strings.HasPrefix(v.Version(), fmt.Sprintf("%d.", majorVersion)) {
			ver, err := hashiVer.NewVersion(v.Version())
			if err != nil {
				continue
			}
			valid = append(valid, namespaceVersion{
				version:   ver,
				namespace: v,
			})
		}
	}

	// return the highest version from valid
	sort.Slice(valid, func(i, j int) bool {
		return valid[i].version.GreaterThan(valid[j].version)
	})

	if len(valid) > 0 {
		return []*distro.Namespace{valid[0].namespace}, true
	}
	return nil, false
}

func (i *Index) CPENamespaces() []*cpe.Namespace {
	return i.cpe
}

func DistroTypeString(ty grypeDistro.Type) string {
	switch ty {
	case grypeDistro.CentOS, grypeDistro.RedHat, grypeDistro.Fedora, grypeDistro.RockyLinux, grypeDistro.AlmaLinux, grypeDistro.Gentoo:
		return strings.ToLower(string(grypeDistro.RedHat))
	}
	return strings.ToLower(string(ty))
}
